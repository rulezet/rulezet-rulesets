rule TTP_XOR_QUAD_CurrentVersionRun_d4d2 {
  strings:
    $key_d4d2 = { 87 bd [2] a3 b3 [2] 88 9f [2] a6 bd [2] b2 a6 [2] bd bc [2] a3 a1 [2] a1 a0 [2] ba a6 [2] a6 a1 [2] ba 8e }

  condition:
    any of them
}