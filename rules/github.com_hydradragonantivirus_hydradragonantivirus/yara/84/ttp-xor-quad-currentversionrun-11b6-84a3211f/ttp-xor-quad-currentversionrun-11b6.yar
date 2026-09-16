rule TTP_XOR_QUAD_CurrentVersionRun_11b6 {
  strings:
    $key_11b6 = { 42 d9 [2] 66 d7 [2] 4d fb [2] 63 d9 [2] 77 c2 [2] 78 d8 [2] 66 c5 [2] 64 c4 [2] 7f c2 [2] 63 c5 [2] 7f ea }

  condition:
    any of them
}