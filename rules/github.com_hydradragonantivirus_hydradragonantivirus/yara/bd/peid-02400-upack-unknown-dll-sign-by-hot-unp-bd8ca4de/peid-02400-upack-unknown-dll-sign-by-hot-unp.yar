rule PEiD_02400_Upack_Unknown__DLL_________Sign_by_hot_UNP_ {
  meta:
    description = "[Upack_Unknown (DLL ???) -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }

  condition:
    $a
}