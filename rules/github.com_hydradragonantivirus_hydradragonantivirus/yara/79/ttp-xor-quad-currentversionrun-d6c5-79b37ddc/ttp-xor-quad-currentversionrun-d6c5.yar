rule TTP_XOR_QUAD_CurrentVersionRun_d6c5 {
  strings:
    $key_d6c5 = { 85 aa [2] a1 a4 [2] 8a 88 [2] a4 aa [2] b0 b1 [2] bf ab [2] a1 b6 [2] a3 b7 [2] b8 b1 [2] a4 b6 [2] b8 99 }

  condition:
    any of them
}