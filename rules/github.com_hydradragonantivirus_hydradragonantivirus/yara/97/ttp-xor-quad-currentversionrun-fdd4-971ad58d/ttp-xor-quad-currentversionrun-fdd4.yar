rule TTP_XOR_QUAD_CurrentVersionRun_fdd4 {
  strings:
    $key_fdd4 = { ae bb [2] 8a b5 [2] a1 99 [2] 8f bb [2] 9b a0 [2] 94 ba [2] 8a a7 [2] 88 a6 [2] 93 a0 [2] 8f a7 [2] 93 88 }

  condition:
    any of them
}