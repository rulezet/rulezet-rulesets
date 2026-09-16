rule TTP_XOR_QUAD_CurrentVersionRun_c357 {
  strings:
    $key_c357 = { 90 38 [2] b4 36 [2] 9f 1a [2] b1 38 [2] a5 23 [2] aa 39 [2] b4 24 [2] b6 25 [2] ad 23 [2] b1 24 [2] ad 0b }

  condition:
    any of them
}