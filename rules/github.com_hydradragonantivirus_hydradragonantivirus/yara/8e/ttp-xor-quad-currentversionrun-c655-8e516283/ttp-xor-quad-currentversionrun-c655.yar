rule TTP_XOR_QUAD_CurrentVersionRun_c655 {
  strings:
    $key_c655 = { 95 3a [2] b1 34 [2] 9a 18 [2] b4 3a [2] a0 21 [2] af 3b [2] b1 26 [2] b3 27 [2] a8 21 [2] b4 26 [2] a8 09 }

  condition:
    any of them
}