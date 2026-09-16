rule TTP_XOR_QUAD_CurrentVersionRun_b8a4 {
  strings:
    $key_b8a4 = { eb cb [2] cf c5 [2] e4 e9 [2] ca cb [2] de d0 [2] d1 ca [2] cf d7 [2] cd d6 [2] d6 d0 [2] ca d7 [2] d6 f8 }

  condition:
    any of them
}