rule TTP_XOR_QUAD_CurrentVersionRun_e874 {
  strings:
    $key_e874 = { bb 1b [2] 9f 15 [2] b4 39 [2] 9a 1b [2] 8e 00 [2] 81 1a [2] 9f 07 [2] 9d 06 [2] 86 00 [2] 9a 07 [2] 86 28 }

  condition:
    any of them
}