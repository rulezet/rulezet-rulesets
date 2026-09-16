rule TTP_XOR_QUAD_CurrentVersionRun_e864 {
  strings:
    $key_e864 = { bb 0b [2] 9f 05 [2] b4 29 [2] 9a 0b [2] 8e 10 [2] 81 0a [2] 9f 17 [2] 9d 16 [2] 86 10 [2] 9a 17 [2] 86 38 }

  condition:
    any of them
}