rule TTP_XOR_QUAD_CurrentVersionRun_d655 {
  strings:
    $key_d655 = { 85 3a [2] a1 34 [2] 8a 18 [2] a4 3a [2] b0 21 [2] bf 3b [2] a1 26 [2] a3 27 [2] b8 21 [2] a4 26 [2] b8 09 }

  condition:
    any of them
}