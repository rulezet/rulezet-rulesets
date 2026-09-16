rule TTP_XOR_QUAD_CurrentVersionRun_c0a4 {
  strings:
    $key_c0a4 = { 93 cb [2] b7 c5 [2] 9c e9 [2] b2 cb [2] a6 d0 [2] a9 ca [2] b7 d7 [2] b5 d6 [2] ae d0 [2] b2 d7 [2] ae f8 }

  condition:
    any of them
}