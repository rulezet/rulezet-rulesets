rule TTP_XOR_QUAD_CurrentVersionRun_c459 {
  strings:
    $key_c459 = { 97 36 [2] b3 38 [2] 98 14 [2] b6 36 [2] a2 2d [2] ad 37 [2] b3 2a [2] b1 2b [2] aa 2d [2] b6 2a [2] aa 05 }

  condition:
    any of them
}