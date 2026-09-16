rule TTP_XOR_QUAD_CurrentVersionRun_c159 {
  strings:
    $key_c159 = { 92 36 [2] b6 38 [2] 9d 14 [2] b3 36 [2] a7 2d [2] a8 37 [2] b6 2a [2] b4 2b [2] af 2d [2] b3 2a [2] af 05 }

  condition:
    any of them
}