rule VirusShareTrojanMulDrop1845357 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDrop1845357.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37768de709f7d565f8807b6e66ad869a350849d9c94e10af35d188bcfe073560"

  strings:
    $x1  = "[!] Error writing shellcode to the target driver, abort" fullword ascii
    $s2  = "kdu -map filename - map driver to the kernel and execute it entry point" fullword ascii
    $s3  = "[!] Error while building shellcode, abort" fullword ascii
    $s4  = "[!] Could not load victim driver, GetLastError %lu" fullword ascii
    $s5  = "[!] Cannot open target process, NTSTATUS (0x%lX)" fullword ascii
    $s6  = "[+] Vulnerable driver file removed" fullword ascii
    $s7  = "[+] Extracting vulnerable driver as \"%ws\"" fullword ascii
    $s8  = "[+] Vulnerable driver opened" fullword ascii
    $s9  = "[+] Vulnerable driver \"%ws\" loaded" fullword ascii
    $s10 = "[+] Victim driver map attempt %lu of %lu" fullword ascii
    $s11 = "[+] Vulnerable driver unloaded" fullword ascii
    $s12 = "[!] Vulnerable driver already loaded" fullword ascii
    $s13 = "[+] Victim DriverUnload 0x%p" fullword ascii
    $s14 = "[+] Process object (EPROCESS) found, 0x%llX" fullword ascii
    $s15 = "[+] Resolving kernel import for input driver" fullword ascii
    $s16 = "[+] Process with PID %llu opened (PROCESS_QUERY_LIMITED_INFORMATION)" fullword ascii
    $s17 = "[+] Process object modified" fullword ascii
    $s18 = "kdu -ps pid       - disable ProtectedProcess for given pid" fullword ascii
    $s19 = "[?] No parameters specified or command not recognized, see Usage for help" fullword ascii
    $s20 = "[?] Usage: kdu Mode [Provider][Command]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}