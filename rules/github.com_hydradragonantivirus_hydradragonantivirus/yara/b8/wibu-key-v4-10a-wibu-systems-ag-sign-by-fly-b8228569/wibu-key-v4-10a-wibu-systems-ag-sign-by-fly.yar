import "pe"
rule WIBU_Key_V4_10A____WIBU_SYSTEMS_AG_____Sign_By_fly {
  strings:
    $a0 = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12 }

  condition:
    $a0 at pe.entry_point
}