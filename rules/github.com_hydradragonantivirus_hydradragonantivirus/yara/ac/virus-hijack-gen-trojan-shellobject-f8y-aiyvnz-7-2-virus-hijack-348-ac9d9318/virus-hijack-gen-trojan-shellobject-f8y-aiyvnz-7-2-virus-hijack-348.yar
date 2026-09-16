rule _Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aiYvnz_7_2_Virus_Hijack_348 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d38ed19cfb2457a7b7ad16624740f7634a10d27be7b9f4d2bdcfa1cd81064139"
    hash2       = "bc0068b0dd00d800c6a777227a1aecddb53b886ed33ee9b6b5694b0edbcb4c31"

  strings:
    $s1  = "English=This operating system is not supported by this installation.  Setup will now terminate." fullword wide
    $s2  = "Polish=Instalacja w tym systemie operacyjnym nie jest obs" fullword wide
    $s3  = "cia nepodporuje tento opera" fullword wide
    $s4  = " Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s5  = "Danish=Installerer Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s6  = "Dutch=Microsoft Visual C++ 2010 SP1 (x64) runtime installeren" fullword wide
    $s7  = "English=Installing Microsoft Visual C++ 2010 SP1 (x64) Runtime." fullword wide
    $s8  = "Finnish=Asennetaan Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s9  = "French=Installation du Runtime Microsoft Visual C++ 2010 SP1 (x64)" fullword wide
    $s10 = "German=Installation der Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s11 = "Hungarian=A Microsoft Visual C++ 2010 SP1 (x64) Runtime telep" fullword wide
    $s12 = "Italian=Installazione di Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s13 = "Korean=Microsoft Visual C++ 2010 SP1 (x64) Runtime " fullword wide
    $s14 = "Norwegian=Installerer Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s15 = "rodowiska uruchomieniowego Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s16 = "taluje sa Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s17 = "Swedish=Installerar Microsoft Visual C++ 2010 SP1 (x64) Runtime" fullword wide
    $s18 = "Turkish=Microsoft Visual C++ 2010 SP1 (x64) Runtime Uygulamas" fullword wide
    $s19 = "7Installing Microsoft Visual C++ 2010 SP1 (x64) Runtime." fullword wide
    $s20 = "Czech=Tato instalace nepodporuje tento opera" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}