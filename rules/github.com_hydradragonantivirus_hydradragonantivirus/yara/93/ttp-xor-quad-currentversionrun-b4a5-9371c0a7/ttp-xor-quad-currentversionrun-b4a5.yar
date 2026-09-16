rule TTP_XOR_QUAD_CurrentVersionRun_b4a5 {
  strings:
    $key_b4a5 = { e7 ca [2] c3 c4 [2] e8 e8 [2] c6 ca [2] d2 d1 [2] dd cb [2] c3 d6 [2] c1 d7 [2] da d1 [2] c6 d6 [2] da f9 }

  condition:
    any of them
}