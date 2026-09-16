rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66753e62603bbf1893f2742df9406a87f3b581294698e634fabe7cacccf19f84"

  strings:
    $s1  = "[+] Imported DLL Name: " fullword ascii
    $s2  = "[+] Binary is running" fullword ascii
    $s3  = "[+] All headers are copied" fullword ascii
    $s4  = "[+] Data is decrypted! " fullword ascii
    $s5  = "EYEY]V\\" fullword ascii
    $s6  = "[+] All sections are copied" fullword ascii
    $s7  = "[+] Cannot load to the preferable address" fullword ascii
    $s8  = "[!] Import Table not found" fullword ascii
    $s9  = "[!] No Reloc Table Found" fullword ascii
    $s10 = "[!] No Relocation Table and Cannot load to the preferable address" fullword ascii
    $s11 = "     [+] Import by ordinal: " fullword ascii
    $s12 = "     [+] Import by name: " fullword ascii
    $s13 = ";wIps%" fullword ascii
    $s14 = "k!,pLeA" fullword ascii
    $s15 = " `Rich" fullword ascii
    $s16 = "MALt()" fullword ascii
    $s17 = "[!] There is a problem in relocation directory" fullword ascii
    $s18 = "[!] Cannot allocate the memory" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}