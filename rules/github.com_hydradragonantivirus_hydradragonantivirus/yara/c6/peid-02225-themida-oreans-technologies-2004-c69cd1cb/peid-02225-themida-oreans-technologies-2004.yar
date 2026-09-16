rule PEiD_02225_Themida____Oreans_Technologies_2004_ {
  meta:
    description = "[Themida -> Oreans Technologies 2004]"
    ep_only     = "true"

  strings:
    $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }

  condition:
    $a
}