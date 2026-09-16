rule TTP_XOR_QUAD_CurrentVersionRun_5ab6 {
  strings:
    $key_5ab6 = { 09 d9 [2] 2d d7 [2] 06 fb [2] 28 d9 [2] 3c c2 [2] 33 d8 [2] 2d c5 [2] 2f c4 [2] 34 c2 [2] 28 c5 [2] 34 ea }

  condition:
    any of them
}