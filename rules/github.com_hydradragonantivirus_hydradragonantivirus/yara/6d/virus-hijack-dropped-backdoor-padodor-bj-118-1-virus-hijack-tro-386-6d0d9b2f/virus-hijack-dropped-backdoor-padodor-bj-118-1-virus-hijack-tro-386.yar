rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_118_1_Virus_Hijack_Tro_386 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_118_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_202_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_219_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2ace93301adf732c37dc77a708f6a6ed9a679ee39254bb5e1eadf0cfe935e80"
    hash2       = "dea5aee731b62bdd9c2c9a234f6c8f21d4967d52f1194056e418e4dc03e163af"
    hash3       = "0dbe642933b76e3311ea2741dc3b509b2824480d4205e6a91425b372b85d999d"

  strings:
    $x1  = "[-] Error injecting remote thread in process: %d" fullword ascii
    $x2  = "  --from-process <name>  Inject from another process, resolves pid" fullword ascii
    $x3  = "  --dump-block <addr> <length> Restrict process memory dump to a particular block" fullword ascii
    $s4  = "  --process-name <name>  Process name to inject" fullword ascii
    $s5  = "  --from <pid>           Inject from another process" fullword ascii
    $s6  = "  --dump <filepath>      Dump process memory with --pid to filepath" fullword ascii
    $s7  = "  --pid <pid>            Process identifier to inject" fullword ascii
    $s8  = "[-] Error opening dump filepath: %S" fullword ascii
    $s9  = "[-] Error obtaining process token: %ld" fullword ascii
    $s10 = "  --dbg <path>           Attach debugger to target process" fullword ascii
    $s11 = "[-] Both --from and --from-process are specified" fullword ascii
    $s12 = "[-] No injection target has been provided!" fullword ascii
    $s13 = "[-] Error launching process: %d" fullword ascii
    $s14 = "[-] Error reading data from process: %ld" fullword ascii
    $s15 = "[-] Error loading monitor into process: %d" fullword ascii
    $s16 = "[-] Error writing data to process: %ld" fullword ascii
    $s17 = "[-] An app path is required when not injecting!" fullword ascii
    $s18 = "  --crt                  CreateRemoteThread injection" fullword ascii
    $s19 = "  --tid <tid>            Thread identifier to inject" fullword ascii
    $s20 = "[-] Both pid and process-name were set!" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}