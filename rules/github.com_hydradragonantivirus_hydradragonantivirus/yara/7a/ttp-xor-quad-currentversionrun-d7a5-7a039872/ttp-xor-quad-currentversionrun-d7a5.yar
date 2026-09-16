rule TTP_XOR_QUAD_CurrentVersionRun_d7a5 {
  strings:
    $key_d7a5 = { 84 ca [2] a0 c4 [2] 8b e8 [2] a5 ca [2] b1 d1 [2] be cb [2] a0 d6 [2] a2 d7 [2] b9 d1 [2] a5 d6 [2] b9 f9 }

  condition:
    any of them
}