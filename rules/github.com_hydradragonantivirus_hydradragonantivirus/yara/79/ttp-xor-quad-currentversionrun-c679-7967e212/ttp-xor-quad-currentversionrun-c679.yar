rule TTP_XOR_QUAD_CurrentVersionRun_c679 {
  strings:
    $key_c679 = { 95 16 [2] b1 18 [2] 9a 34 [2] b4 16 [2] a0 0d [2] af 17 [2] b1 0a [2] b3 0b [2] a8 0d [2] b4 0a [2] a8 25 }

  condition:
    any of them
}