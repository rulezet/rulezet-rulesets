rule TTP_XOR_QUAD_CurrentVersionRun_c0aa {
  strings:
    $key_c0aa = { 93 c5 [2] b7 cb [2] 9c e7 [2] b2 c5 [2] a6 de [2] a9 c4 [2] b7 d9 [2] b5 d8 [2] ae de [2] b2 d9 [2] ae f6 }

  condition:
    any of them
}