rule TTP_XOR_QUAD_CurrentVersionRun_c355 {
  strings:
    $key_c355 = { 90 3a [2] b4 34 [2] 9f 18 [2] b1 3a [2] a5 21 [2] aa 3b [2] b4 26 [2] b6 27 [2] ad 21 [2] b1 26 [2] ad 09 }

  condition:
    any of them
}