rule TTP_XOR_QUAD_CurrentVersionRun_4bb6 {
  strings:
    $key_4bb6 = { 18 d9 [2] 3c d7 [2] 17 fb [2] 39 d9 [2] 2d c2 [2] 22 d8 [2] 3c c5 [2] 3e c4 [2] 25 c2 [2] 39 c5 [2] 25 ea }

  condition:
    any of them
}