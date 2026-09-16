rule TTP_XOR_QUAD_CurrentVersionRun_e848 {
  strings:
    $key_e848 = { bb 27 [2] 9f 29 [2] b4 05 [2] 9a 27 [2] 8e 3c [2] 81 26 [2] 9f 3b [2] 9d 3a [2] 86 3c [2] 9a 3b [2] 86 14 }

  condition:
    any of them
}