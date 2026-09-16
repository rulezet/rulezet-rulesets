rule TTP_XOR_QUAD_CurrentVersionRun_c1d2 {
  strings:
    $key_c1d2 = { 92 bd [2] b6 b3 [2] 9d 9f [2] b3 bd [2] a7 a6 [2] a8 bc [2] b6 a1 [2] b4 a0 [2] af a6 [2] b3 a1 [2] af 8e }

  condition:
    any of them
}