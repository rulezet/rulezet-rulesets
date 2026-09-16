rule TTP_XOR_QUAD_CurrentVersionRun_f8da {
  strings:
    $key_f8da = { ab b5 [2] 8f bb [2] a4 97 [2] 8a b5 [2] 9e ae [2] 91 b4 [2] 8f a9 [2] 8d a8 [2] 96 ae [2] 8a a9 [2] 96 86 }

  condition:
    any of them
}