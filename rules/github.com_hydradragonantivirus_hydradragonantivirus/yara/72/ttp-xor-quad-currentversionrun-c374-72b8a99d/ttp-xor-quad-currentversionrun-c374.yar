rule TTP_XOR_QUAD_CurrentVersionRun_c374 {
  strings:
    $key_c374 = { 90 1b [2] b4 15 [2] 9f 39 [2] b1 1b [2] a5 00 [2] aa 1a [2] b4 07 [2] b6 06 [2] ad 00 [2] b1 07 [2] ad 28 }

  condition:
    any of them
}