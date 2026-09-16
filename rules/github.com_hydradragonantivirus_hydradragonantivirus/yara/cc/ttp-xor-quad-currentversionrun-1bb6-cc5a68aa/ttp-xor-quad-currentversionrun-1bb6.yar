rule TTP_XOR_QUAD_CurrentVersionRun_1bb6 {
  strings:
    $key_1bb6 = { 48 d9 [2] 6c d7 [2] 47 fb [2] 69 d9 [2] 7d c2 [2] 72 d8 [2] 6c c5 [2] 6e c4 [2] 75 c2 [2] 69 c5 [2] 75 ea }

  condition:
    any of them
}