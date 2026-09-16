rule TTP_XOR_QUAD_CurrentVersionRun_c1d7 {
  strings:
    $key_c1d7 = { 92 b8 [2] b6 b6 [2] 9d 9a [2] b3 b8 [2] a7 a3 [2] a8 b9 [2] b6 a4 [2] b4 a5 [2] af a3 [2] b3 a4 [2] af 8b }

  condition:
    any of them
}