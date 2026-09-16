rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aqns23l_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92f95cf89c0a5195254c05805b5b0c06f3c7b63ceae9525bcaf486606b02d0e7"

  strings:
    $s1 = "shutdown /f /r /c \"Your computer is infected by clown.exe\" /t 300" fullword ascii
    $s2 = "<clown, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
    $s3 = "o para compatibilidade" fullword ascii
    $s4 = " optar por participar. Aplicativos do Windows Forms direcionados ao .NET Framework 4.6 que aderirem a essa configura" fullword ascii
    $s5 = "es de Manifesto UAC" fullword ascii
    $s6 = "  <!-- Habilita temas para caixas de di" fullword ascii
    $s7 = " mais elevados. Aplicativos WPF (Windows Presentation Foundation) t" fullword ascii
    $s8 = " automaticamente escalado pelo Windows em DPIs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}