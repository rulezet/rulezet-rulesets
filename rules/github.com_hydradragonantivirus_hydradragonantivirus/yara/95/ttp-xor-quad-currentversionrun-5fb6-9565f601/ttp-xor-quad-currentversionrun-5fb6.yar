rule TTP_XOR_QUAD_CurrentVersionRun_5fb6 {
  strings:
    $key_5fb6 = { 0c d9 [2] 28 d7 [2] 03 fb [2] 2d d9 [2] 39 c2 [2] 36 d8 [2] 28 c5 [2] 2a c4 [2] 31 c2 [2] 2d c5 [2] 31 ea }

  condition:
    any of them
}