rule TTP_XOR_QUAD_CurrentVersionRun_e854 {
  strings:
    $key_e854 = { bb 3b [2] 9f 35 [2] b4 19 [2] 9a 3b [2] 8e 20 [2] 81 3a [2] 9f 27 [2] 9d 26 [2] 86 20 [2] 9a 27 [2] 86 08 }

  condition:
    any of them
}