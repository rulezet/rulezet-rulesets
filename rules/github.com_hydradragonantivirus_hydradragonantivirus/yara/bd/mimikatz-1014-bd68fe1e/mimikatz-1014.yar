import "pe"
rule mimikatz_1014 {
  meta:
    description = "exe - file mimikatz.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-01-18"
    hash1       = "99d8d56435e780352a8362dd5cb3857949c6ff5585e81b287527cd6e52a092c1"

  strings:
    $x1  = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
    $x2  = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx user (%s)" fullword wide
    $x3  = "ERROR kuhl_m_lsadump_lsa ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
    $x4  = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" fullword wide
    $x5  = "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" fullword wide
    $x6  = "ERROR kuhl_m_lsadump_trust ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
    $x7  = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" fullword wide
    $x8  = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" fullword wide
    $x9  = "ERROR kuhl_m_lsadump_netsync ; I_NetServerTrustPasswordsGet (0x%08x)" fullword wide
    $x10 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
    $x11 = "ERROR kuhl_m_kernel_processProtect ; Argument /process:program.exe or /pid:processid needed" fullword wide
    $x12 = "ERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (%hu)" fullword wide
    $x13 = "ERROR kuhl_m_lsadump_sam ; kull_m_registry_RegOpenKeyEx (SAM) (0x%08x)" fullword wide
    $x14 = "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:0x%08x - R:0x%08x)" fullword wide
    $x15 = "ERROR kuhl_m_lsadump_enumdomains_users ; /user or /rid is needed" fullword wide
    $x16 = "ERROR kuhl_m_lsadump_changentlm ; Argument /oldpassword: or /oldntlm: is needed" fullword wide
    $x17 = "livessp.dll" fullword wide  
    $x18 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" fullword wide
    $x19 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
    $x20 = "ERROR kuhl_m_lsadump_getKeyFromGUID ; kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x" fullword wide

  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and
    (pe.imphash() == "a0444dc502edb626311492eb9abac8ec" or 1 of ($x*))
}