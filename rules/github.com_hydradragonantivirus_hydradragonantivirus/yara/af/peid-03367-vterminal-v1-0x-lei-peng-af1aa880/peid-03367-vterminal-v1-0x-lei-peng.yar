rule PEiD_03367_Vterminal_V1_0X____Lei_Peng_ {
  meta:
    description = "[Vterminal V1.0X -> Lei Peng]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 }

  condition:
    $a
}