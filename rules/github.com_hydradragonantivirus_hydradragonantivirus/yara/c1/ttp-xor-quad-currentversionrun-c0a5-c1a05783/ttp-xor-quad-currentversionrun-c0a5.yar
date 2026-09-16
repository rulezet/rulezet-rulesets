rule TTP_XOR_QUAD_CurrentVersionRun_c0a5 {
  strings:
    $key_c0a5 = { 93 ca [2] b7 c4 [2] 9c e8 [2] b2 ca [2] a6 d1 [2] a9 cb [2] b7 d6 [2] b5 d7 [2] ae d1 [2] b2 d6 [2] ae f9 }

  condition:
    any of them
}