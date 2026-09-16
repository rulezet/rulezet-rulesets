rule TTP_XOR_QUAD_CurrentVersionRun_c359 {
  strings:
    $key_c359 = { 90 36 [2] b4 38 [2] 9f 14 [2] b1 36 [2] a5 2d [2] aa 37 [2] b4 2a [2] b6 2b [2] ad 2d [2] b1 2a [2] ad 05 }

  condition:
    any of them
}