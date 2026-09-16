rule TTP_XOR_QUAD_CurrentVersionRun_f0c6 {
  strings:
    $key_f0c6 = { a3 a9 [2] 87 a7 [2] ac 8b [2] 82 a9 [2] 96 b2 [2] 99 a8 [2] 87 b5 [2] 85 b4 [2] 9e b2 [2] 82 b5 [2] 9e 9a }

  condition:
    any of them
}