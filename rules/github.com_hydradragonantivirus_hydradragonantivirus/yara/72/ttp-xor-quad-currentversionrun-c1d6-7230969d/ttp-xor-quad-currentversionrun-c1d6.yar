rule TTP_XOR_QUAD_CurrentVersionRun_c1d6 {
  strings:
    $key_c1d6 = { 92 b9 [2] b6 b7 [2] 9d 9b [2] b3 b9 [2] a7 a2 [2] a8 b8 [2] b6 a5 [2] b4 a4 [2] af a2 [2] b3 a5 [2] af 8a }

  condition:
    any of them
}