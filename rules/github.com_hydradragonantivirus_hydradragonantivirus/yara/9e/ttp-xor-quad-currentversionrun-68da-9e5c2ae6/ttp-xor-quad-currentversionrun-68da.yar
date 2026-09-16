rule TTP_XOR_QUAD_CurrentVersionRun_68da {
  strings:
    $key_68da = { 3b b5 [2] 1f bb [2] 34 97 [2] 1a b5 [2] 0e ae [2] 01 b4 [2] 1f a9 [2] 1d a8 [2] 06 ae [2] 1a a9 [2] 06 86 }

  condition:
    any of them
}