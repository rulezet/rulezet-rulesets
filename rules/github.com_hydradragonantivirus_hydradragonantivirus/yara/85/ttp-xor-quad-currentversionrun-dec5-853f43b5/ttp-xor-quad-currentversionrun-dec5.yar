rule TTP_XOR_QUAD_CurrentVersionRun_dec5 {
  strings:
    $key_dec5 = { 8d aa [2] a9 a4 [2] 82 88 [2] ac aa [2] b8 b1 [2] b7 ab [2] a9 b6 [2] ab b7 [2] b0 b1 [2] ac b6 [2] b0 99 }

  condition:
    any of them
}