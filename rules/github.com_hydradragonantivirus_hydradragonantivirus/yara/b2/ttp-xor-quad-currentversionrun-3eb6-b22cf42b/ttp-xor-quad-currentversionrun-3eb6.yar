rule TTP_XOR_QUAD_CurrentVersionRun_3eb6 {
  strings:
    $key_3eb6 = { 6d d9 [2] 49 d7 [2] 62 fb [2] 4c d9 [2] 58 c2 [2] 57 d8 [2] 49 c5 [2] 4b c4 [2] 50 c2 [2] 4c c5 [2] 50 ea }

  condition:
    any of them
}