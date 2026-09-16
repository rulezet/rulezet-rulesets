rule TTP_XOR_QUAD_CurrentVersionRun_51b6 {
  strings:
    $key_51b6 = { 02 d9 [2] 26 d7 [2] 0d fb [2] 23 d9 [2] 37 c2 [2] 38 d8 [2] 26 c5 [2] 24 c4 [2] 3f c2 [2] 23 c5 [2] 3f ea }

  condition:
    any of them
}