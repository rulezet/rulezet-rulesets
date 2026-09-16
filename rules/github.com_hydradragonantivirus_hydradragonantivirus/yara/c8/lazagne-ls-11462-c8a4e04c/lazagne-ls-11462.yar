import "pe"
rule lazagne_ls_11462 {
  meta:
    description = "lazagne - file ls.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2022-05-01"
    hash1       = "8764131983eac23033c460833de5e439a4c475ad94cfd561d80cb62f86ff50a4"

  strings:
    $s1  = "pypykatz.lsadecryptor.packages.msv.templates(" fullword ascii
    $s2  = "pypykatz.lsadecryptor.packages.ssp.templates(" fullword ascii
    $s3  = "pypykatz.lsadecryptor.packages.kerberos.templates(" fullword ascii
    $s4  = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
    $s5  = "pypykatz.commons.readers.local.common.kernel32(" fullword ascii
    $s6  = "pypykatz.lsadecryptor.packages.dpapi.templates(" fullword ascii
    $s7  = "pypykatz.lsadecryptor.packages.credman.templates(" fullword ascii
    $s8  = "pypykatz.lsadecryptor.packages.livessp.templates(" fullword ascii
    $s9  = "pypykatz.lsadecryptor.packages.wdigest.templates(" fullword ascii
    $s10 = "pypykatz.lsadecryptor.packages.tspkg.templates(" fullword ascii
    $s11 = "pypykatz.lsadecryptor.lsa_templates(" fullword ascii
    $s12 = "lazagne.config.lib.memorpy.SunProcess(" fullword ascii
    $s13 = "lazagne.config.lib.memorpy.BaseProcess(" fullword ascii
    $s14 = "lazagne.config.lib.memorpy.OSXProcess(" fullword ascii
    $s15 = "lazagne.config.lib.memorpy.Process(" fullword ascii
    $s16 = "lazagne.config.lib.memorpy.WinProcess(" fullword ascii
    $s17 = "lazagne.config.lib.memorpy.LinProcess(" fullword ascii
    $s18 = "lazagne.config.execute_cmd(" fullword ascii
    $s19 = "pypykatz.commons.readers.local.common.version(" fullword ascii
    $s20 = "pypykatz.commons.readers.local.common.privileges(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 23000KB and
    (pe.imphash() == "a62ff465f3ead2e578f02d3a2d749b7b" or 8 of them)
}