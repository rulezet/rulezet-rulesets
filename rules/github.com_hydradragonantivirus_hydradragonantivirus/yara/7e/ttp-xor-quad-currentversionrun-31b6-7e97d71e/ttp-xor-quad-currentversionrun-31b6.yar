rule TTP_XOR_QUAD_CurrentVersionRun_31b6 {
  strings:
    $key_31b6 = { 62 d9 [2] 46 d7 [2] 6d fb [2] 43 d9 [2] 57 c2 [2] 58 d8 [2] 46 c5 [2] 44 c4 [2] 5f c2 [2] 43 c5 [2] 5f ea }

  condition:
    any of them
}