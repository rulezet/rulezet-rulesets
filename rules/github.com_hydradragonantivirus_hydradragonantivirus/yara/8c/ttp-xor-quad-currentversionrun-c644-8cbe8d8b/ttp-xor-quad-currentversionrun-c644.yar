rule TTP_XOR_QUAD_CurrentVersionRun_c644 {
  strings:
    $key_c644 = { 95 2b [2] b1 25 [2] 9a 09 [2] b4 2b [2] a0 30 [2] af 2a [2] b1 37 [2] b3 36 [2] a8 30 [2] b4 37 [2] a8 18 }

  condition:
    any of them
}