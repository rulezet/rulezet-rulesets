rule TTP_XOR_QUAD_CurrentVersionRun_1eb6 {
  strings:
    $key_1eb6 = { 4d d9 [2] 69 d7 [2] 42 fb [2] 6c d9 [2] 78 c2 [2] 77 d8 [2] 69 c5 [2] 6b c4 [2] 70 c2 [2] 6c c5 [2] 70 ea }

  condition:
    any of them
}