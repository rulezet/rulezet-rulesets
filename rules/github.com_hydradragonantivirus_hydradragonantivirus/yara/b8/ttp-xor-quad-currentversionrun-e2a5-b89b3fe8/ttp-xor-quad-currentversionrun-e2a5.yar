rule TTP_XOR_QUAD_CurrentVersionRun_e2a5 {
  strings:
    $key_e2a5 = { b1 ca [2] 95 c4 [2] be e8 [2] 90 ca [2] 84 d1 [2] 8b cb [2] 95 d6 [2] 97 d7 [2] 8c d1 [2] 90 d6 [2] 8c f9 }

  condition:
    any of them
}