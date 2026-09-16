rule TTP_XOR_QUAD_CurrentVersionRun_d6d2 {
  strings:
    $key_d6d2 = { 85 bd [2] a1 b3 [2] 8a 9f [2] a4 bd [2] b0 a6 [2] bf bc [2] a1 a1 [2] a3 a0 [2] b8 a6 [2] a4 a1 [2] b8 8e }

  condition:
    any of them
}