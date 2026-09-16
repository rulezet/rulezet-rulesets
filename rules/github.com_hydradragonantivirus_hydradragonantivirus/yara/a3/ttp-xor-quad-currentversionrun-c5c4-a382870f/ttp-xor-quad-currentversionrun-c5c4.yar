rule TTP_XOR_QUAD_CurrentVersionRun_c5c4 {
  strings:
    $key_c5c4 = { 96 ab [2] b2 a5 [2] 99 89 [2] b7 ab [2] a3 b0 [2] ac aa [2] b2 b7 [2] b0 b6 [2] ab b0 [2] b7 b7 [2] ab 98 }

  condition:
    any of them
}