rule TTP_XOR_QUAD_CurrentVersionRun_3bb6 {
  strings:
    $key_3bb6 = { 68 d9 [2] 4c d7 [2] 67 fb [2] 49 d9 [2] 5d c2 [2] 52 d8 [2] 4c c5 [2] 4e c4 [2] 55 c2 [2] 49 c5 [2] 55 ea }

  condition:
    any of them
}