rule TTP_XOR_QUAD_CurrentVersionRun_f1d6 {
  strings:
    $key_f1d6 = { a2 b9 [2] 86 b7 [2] ad 9b [2] 83 b9 [2] 97 a2 [2] 98 b8 [2] 86 a5 [2] 84 a4 [2] 9f a2 [2] 83 a5 [2] 9f 8a }

  condition:
    any of them
}