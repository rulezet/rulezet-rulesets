rule TTP_XOR_QUAD_CurrentVersionRun_e875 {
  strings:
    $key_e875 = { bb 1a [2] 9f 14 [2] b4 38 [2] 9a 1a [2] 8e 01 [2] 81 1b [2] 9f 06 [2] 9d 07 [2] 86 01 [2] 9a 06 [2] 86 29 }

  condition:
    any of them
}