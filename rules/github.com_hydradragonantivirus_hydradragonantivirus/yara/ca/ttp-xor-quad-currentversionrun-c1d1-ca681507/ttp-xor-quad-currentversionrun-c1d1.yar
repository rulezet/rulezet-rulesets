rule TTP_XOR_QUAD_CurrentVersionRun_c1d1 {
  strings:
    $key_c1d1 = { 92 be [2] b6 b0 [2] 9d 9c [2] b3 be [2] a7 a5 [2] a8 bf [2] b6 a2 [2] b4 a3 [2] af a5 [2] b3 a2 [2] af 8d }

  condition:
    any of them
}