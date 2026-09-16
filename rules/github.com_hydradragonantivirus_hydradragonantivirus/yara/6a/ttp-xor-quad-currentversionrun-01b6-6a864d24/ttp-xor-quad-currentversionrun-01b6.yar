rule TTP_XOR_QUAD_CurrentVersionRun_01b6 {
  strings:
    $key_01b6 = { 52 d9 [2] 76 d7 [2] 5d fb [2] 73 d9 [2] 67 c2 [2] 68 d8 [2] 76 c5 [2] 74 c4 [2] 6f c2 [2] 73 c5 [2] 6f ea }

  condition:
    any of them
}