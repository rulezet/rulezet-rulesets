rule TTP_XOR_QUAD_CurrentVersionRun_d1d2 {
  strings:
    $key_d1d2 = { 82 bd [2] a6 b3 [2] 8d 9f [2] a3 bd [2] b7 a6 [2] b8 bc [2] a6 a1 [2] a4 a0 [2] bf a6 [2] a3 a1 [2] bf 8e }

  condition:
    any of them
}