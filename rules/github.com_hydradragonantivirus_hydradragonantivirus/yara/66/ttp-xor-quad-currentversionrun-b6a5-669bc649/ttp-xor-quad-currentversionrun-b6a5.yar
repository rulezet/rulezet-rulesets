rule TTP_XOR_QUAD_CurrentVersionRun_b6a5 {
  strings:
    $key_b6a5 = { e5 ca [2] c1 c4 [2] ea e8 [2] c4 ca [2] d0 d1 [2] df cb [2] c1 d6 [2] c3 d7 [2] d8 d1 [2] c4 d6 [2] d8 f9 }

  condition:
    any of them
}