rule TTP_XOR_QUAD_CurrentVersionRun_e867 {
  strings:
    $key_e867 = { bb 08 [2] 9f 06 [2] b4 2a [2] 9a 08 [2] 8e 13 [2] 81 09 [2] 9f 14 [2] 9d 15 [2] 86 13 [2] 9a 14 [2] 86 3b }

  condition:
    any of them
}