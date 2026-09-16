rule TTP_XOR_QUAD_CurrentVersionRun_e1b6 {
  strings:
    $key_e1b6 = { b2 d9 [2] 96 d7 [2] bd fb [2] 93 d9 [2] 87 c2 [2] 88 d8 [2] 96 c5 [2] 94 c4 [2] 8f c2 [2] 93 c5 [2] 8f ea }

  condition:
    any of them
}