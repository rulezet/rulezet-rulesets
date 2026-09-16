rule TTP_XOR_QUAD_CurrentVersionRun_e3a5 {
  strings:
    $key_e3a5 = { b0 ca [2] 94 c4 [2] bf e8 [2] 91 ca [2] 85 d1 [2] 8a cb [2] 94 d6 [2] 96 d7 [2] 8d d1 [2] 91 d6 [2] 8d f9 }

  condition:
    any of them
}