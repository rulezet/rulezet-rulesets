rule Virus_Hijack_Gen_Trojan_ShellObject_h8X_a853Pwn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8X@a853Pwn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f1e14d5240271ff4ac975fa3457b762e695f2f1f15356c945c106739ac9345c"

  strings:
    $s1  = "CDDisplayOrder/></OfflineBoot><ExecState HaveTargetVolume=\"True\" TargetVolumeAccessible=\"True\" TargetVolumeRootSet=\"True\" " ascii
    $s2  = "<c:contact c:Version=\"1\" xmlns:c=\"http://schemas.microsoft.com/Contact\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instanc" ascii
    $s3  = "visua<ResetSession TargetSet=\"True\" TargetSignature=\"{8CB48B08-DE41-40C2-A311-CAEA51CD6F8E}\" TargetCapacity=\"137438953472\"" ascii
    $s4  = "<c:ContactIDCollection><c:ContactID c:ElementID=\"245c34d7-5e55-4dc1-b53e-8aed97dd4070\"><c:Value>98215940-a2e5-4a51-9af5-5495b5" ascii
    $s5  = "05-13T22:32:55Z\"><c:Value c:ContentType=\"image/bmp\" c:Version=\"1\" c:ModificationDate=\"2019-05-13T22:32:55Z\">Qk04wAAAAAAAA" ascii
    $s6  = "/s9e/s1Z/s1Y/s1Z/s1ZAAA=</c:Value><c:LabelCollection><c:Label c:Version=\"1\" c:ModificationDate=\"2019-05-13T22:32:55Z\">UserTi" ascii
    $s7  = "/s9e/s1Z/s1Y/s1Z/s1ZAAA=</c:Value><c:LabelCollection><c:Label c:Version=\"1\" c:ModificationDate=\"2019-05-13T22:32:55Z\">UserTi" ascii
    $s8  = "76a6</c:Value></c:ContactID></c:ContactIDCollection><c:NameCollection><c:Name c:ElementID=\"291d3737-7e85-413b-a977-d161a0915ae8" ascii
    $s9  = "<c:CreationDate>2019-05-13T22:32:55Z</c:CreationDate><c:Extended xsi:nil=\"true\"/>" fullword ascii
    $s10 = "c:Label></c:LabelCollection></c:Photo></c:PhotoCollection></c:contact>" fullword ascii
    $s11 = "<c:ContactIDCollection><c:ContactID c:ElementID=\"245c34d7-5e55-4dc1-b53e-8aed97dd4070\"><c:Value>98215940-a2e5-4a51-9af5-5495b5" ascii
    $s12 = "nDate=\"2019-05-13T22:32:55Z\"><c:Photo c:ElementID=\"7f99f97c-c164-4de7-9796-76d67f7702d0\" c:Version=\"1\" c:ModificationDate=" ascii
    $s13 = "><c:FormattedName>Agamennone Monaldo</c:FormattedName></c:Name></c:NameCollection><c:PhotoCollection c:Version=\"1\" c:Modificat" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}