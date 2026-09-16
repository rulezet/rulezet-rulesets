rule Virus_Hijack_GenPack_Backdoor_Hangup_B_50 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_50.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ec58ac244d481e6a3662f04fc5adecaead2c8e19bccacfdb1632be4a72b5e2d"

  strings:
    $s1 = "t/create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}