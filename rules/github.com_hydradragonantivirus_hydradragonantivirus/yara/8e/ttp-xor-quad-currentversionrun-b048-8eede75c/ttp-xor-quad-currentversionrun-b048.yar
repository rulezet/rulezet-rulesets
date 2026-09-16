rule TTP_XOR_QUAD_CurrentVersionRun_b048 {
  strings:
    $key_b048 = { e3 27 [2] c7 29 [2] ec 05 [2] c2 27 [2] d6 3c [2] d9 26 [2] c7 3b [2] c5 3a [2] de 3c [2] c2 3b [2] de 14 }

  condition:
    any of them
}