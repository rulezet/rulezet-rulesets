rule TTP_XOR_QUAD_CurrentVersionRun_c5aa {
  strings:
    $key_c5aa = { 96 c5 [2] b2 cb [2] 99 e7 [2] b7 c5 [2] a3 de [2] ac c4 [2] b2 d9 [2] b0 d8 [2] ab de [2] b7 d9 [2] ab f6 }

  condition:
    any of them
}