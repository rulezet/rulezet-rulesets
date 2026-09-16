rule TTP_XOR_QUAD_CurrentVersionRun_e6aa {
  strings:
    $key_e6aa = { b5 c5 [2] 91 cb [2] ba e7 [2] 94 c5 [2] 80 de [2] 8f c4 [2] 91 d9 [2] 93 d8 [2] 88 de [2] 94 d9 [2] 88 f6 }

  condition:
    any of them
}