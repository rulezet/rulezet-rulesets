rule TTP_XOR_QUAD_CurrentVersionRun_48da {
  strings:
    $key_48da = { 1b b5 [2] 3f bb [2] 14 97 [2] 3a b5 [2] 2e ae [2] 21 b4 [2] 3f a9 [2] 3d a8 [2] 26 ae [2] 3a a9 [2] 26 86 }

  condition:
    any of them
}