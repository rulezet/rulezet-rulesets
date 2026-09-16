rule TTP_XOR_QUAD_CurrentVersionRun_58da {
  strings:
    $key_58da = { 0b b5 [2] 2f bb [2] 04 97 [2] 2a b5 [2] 3e ae [2] 31 b4 [2] 2f a9 [2] 2d a8 [2] 36 ae [2] 2a a9 [2] 36 86 }

  condition:
    any of them
}