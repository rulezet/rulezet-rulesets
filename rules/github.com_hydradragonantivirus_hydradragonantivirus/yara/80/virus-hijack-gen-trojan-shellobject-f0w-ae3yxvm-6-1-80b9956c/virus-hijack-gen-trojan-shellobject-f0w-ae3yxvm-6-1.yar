rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0978254685cf17de6f23dcaaccdc02ef154b50f4bf2feedbe3d1a3bf3c4d086"

  strings:
    $x1  = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $x2  = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"JRSoft.INNO.exehead\" type=\"win32\"/><description>JR" ascii
    $s3  = "Contact: HH.Feedback@GMail.CoM" fullword wide
    $s4  = "Best working OS:WinXP SP2. Header Script last modified: 2006" fullword wide
    $s5  = "Distributed as Demo of Software Localization, for evaluation only, NOT for commercial use. Ready to enter into business cooperat" wide
    $s6  = "O Install System v5.16</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Com" ascii
    $s7  = "NOT for commercial use!" fullword wide
    $s8  = "[PcMedik] Localized Edition (in Chinese)" fullword wide
    $s9  = "LordFox' Localization Opus" fullword wide
    $s10 = "dependency></assembly>l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}