rule TTP_XOR_QUAD_CurrentVersionRun_38da {
  strings:
    $key_38da = { 6b b5 [2] 4f bb [2] 64 97 [2] 4a b5 [2] 5e ae [2] 51 b4 [2] 4f a9 [2] 4d a8 [2] 56 ae [2] 4a a9 [2] 56 86 }

  condition:
    any of them
}