rule TTP_XOR_QUAD_CurrentVersionRun_0eb6 {
  strings:
    $key_0eb6 = { 5d d9 [2] 79 d7 [2] 52 fb [2] 7c d9 [2] 68 c2 [2] 67 d8 [2] 79 c5 [2] 7b c4 [2] 60 c2 [2] 7c c5 [2] 60 ea }

  condition:
    any of them
}