rule TTP_XOR_QUAD_CurrentVersionRun_c373 {
  strings:
    $key_c373 = { 90 1c [2] b4 12 [2] 9f 3e [2] b1 1c [2] a5 07 [2] aa 1d [2] b4 00 [2] b6 01 [2] ad 07 [2] b1 00 [2] ad 2f }

  condition:
    any of them
}