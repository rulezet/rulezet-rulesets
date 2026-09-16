rule TTP_XOR_QUAD_CurrentVersionRun_71c2 {
  strings:
    $key_71c2 = { 22 ad [2] 06 a3 [2] 2d 8f [2] 03 ad [2] 17 b6 [2] 18 ac [2] 06 b1 [2] 04 b0 [2] 1f b6 [2] 03 b1 [2] 1f 9e }

  condition:
    any of them
}