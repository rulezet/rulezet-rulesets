rule TTP_XOR_QUAD_CurrentVersionRun_3daa {
  strings:
    $key_3daa = { 6e c5 [2] 4a cb [2] 61 e7 [2] 4f c5 [2] 5b de [2] 54 c4 [2] 4a d9 [2] 48 d8 [2] 53 de [2] 4f d9 [2] 53 f6 }

  condition:
    any of them
}