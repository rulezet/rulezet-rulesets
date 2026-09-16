rule TTP_XOR_QUAD_CurrentVersionRun_71c3 {
  strings:
    $key_71c3 = { 22 ac [2] 06 a2 [2] 2d 8e [2] 03 ac [2] 17 b7 [2] 18 ad [2] 06 b0 [2] 04 b1 [2] 1f b7 [2] 03 b0 [2] 1f 9f }

  condition:
    any of them
}