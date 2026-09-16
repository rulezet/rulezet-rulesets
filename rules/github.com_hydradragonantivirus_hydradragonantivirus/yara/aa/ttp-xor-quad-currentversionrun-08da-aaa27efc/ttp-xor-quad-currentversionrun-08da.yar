rule TTP_XOR_QUAD_CurrentVersionRun_08da {
  strings:
    $key_08da = { 5b b5 [2] 7f bb [2] 54 97 [2] 7a b5 [2] 6e ae [2] 61 b4 [2] 7f a9 [2] 7d a8 [2] 66 ae [2] 7a a9 [2] 66 86 }

  condition:
    any of them
}