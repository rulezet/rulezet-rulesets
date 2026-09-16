rule TTP_XOR_QUAD_CurrentVersionRun_e869 {
  strings:
    $key_e869 = { bb 06 [2] 9f 08 [2] b4 24 [2] 9a 06 [2] 8e 1d [2] 81 07 [2] 9f 1a [2] 9d 1b [2] 86 1d [2] 9a 1a [2] 86 35 }

  condition:
    any of them
}