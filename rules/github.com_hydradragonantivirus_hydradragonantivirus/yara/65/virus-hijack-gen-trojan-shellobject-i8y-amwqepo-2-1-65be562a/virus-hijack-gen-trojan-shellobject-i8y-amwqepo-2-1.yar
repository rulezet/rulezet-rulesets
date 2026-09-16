rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_amWqEpo_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@amWqEpo_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e8f80033382fc04d72c15d49c574c4a8025fdbe01647b1fd041b993540fa764"

  strings:
    $s1 = "<Module>{740658e4-4981-4e7c-88a3-1964ebdfe607}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}