rule TTP_XOR_QUAD_CurrentVersionRun_4aaa {
  strings:
    $key_4aaa = { 19 c5 [2] 3d cb [2] 16 e7 [2] 38 c5 [2] 2c de [2] 23 c4 [2] 3d d9 [2] 3f d8 [2] 24 de [2] 38 d9 [2] 24 f6 }

  condition:
    any of them
}