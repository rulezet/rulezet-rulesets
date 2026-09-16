rule TTP_XOR_QUAD_CurrentVersionRun_c759 {
  strings:
    $key_c759 = { 94 36 [2] b0 38 [2] 9b 14 [2] b5 36 [2] a1 2d [2] ae 37 [2] b0 2a [2] b2 2b [2] a9 2d [2] b5 2a [2] a9 05 }

  condition:
    any of them
}