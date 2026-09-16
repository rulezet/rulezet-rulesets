import "pe"
rule _Trojan_Danger_Gen_Trojan_FileInfector_mmJfa0A48Fd_Virus_Hijack__460 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Trojan.FileInfector.mmJfa0A48Fd.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "882582dbaeb47ffff27b47f45698163207d162e9ca4b9e850b7b2942c5a23391"
    hash2       = "3dd53cf900117c74465aeccb713c65059c45b9b38fdfdc5cc23111d9978de73d"

  strings:
    $s1 = "Unable to launch cmd " fullword wide
    $s2 = "Received from standard error: " fullword wide
    $s3 = "Administrator permission required" fullword wide
    $s4 = "Unknown exception: " fullword wide
    $s5 = "Unpack: " fullword wide
    $s6 = "Found interesting file: " fullword wide
    $s7 = "Unable to find 7z" fullword wide
    $s8 = "Received from standard out: " fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "895fbb56c02c3d2bca3125cef5da8730" and (all of them)
    ) or (all of them)
}