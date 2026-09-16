rule TTP_XOR_QUAD_CurrentVersionRun_cfd6 {
  strings:
    $key_cfd6 = { 9c b9 [2] b8 b7 [2] 93 9b [2] bd b9 [2] a9 a2 [2] a6 b8 [2] b8 a5 [2] ba a4 [2] a1 a2 [2] bd a5 [2] a1 8a }

  condition:
    any of them
}