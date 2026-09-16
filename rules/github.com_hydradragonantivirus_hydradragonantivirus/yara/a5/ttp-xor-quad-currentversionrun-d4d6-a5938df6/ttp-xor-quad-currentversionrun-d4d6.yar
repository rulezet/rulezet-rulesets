rule TTP_XOR_QUAD_CurrentVersionRun_d4d6 {
  strings:
    $key_d4d6 = { 87 b9 [2] a3 b7 [2] 88 9b [2] a6 b9 [2] b2 a2 [2] bd b8 [2] a3 a5 [2] a1 a4 [2] ba a2 [2] a6 a5 [2] ba 8a }

  condition:
    any of them
}