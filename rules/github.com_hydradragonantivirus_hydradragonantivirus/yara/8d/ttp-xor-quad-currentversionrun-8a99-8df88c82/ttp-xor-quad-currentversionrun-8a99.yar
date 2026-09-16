rule TTP_XOR_QUAD_CurrentVersionRun_8a99 {
  strings:
    $key_8a99 = { d9 f6 [2] fd f8 [2] d6 d4 [2] f8 f6 [2] ec ed [2] e3 f7 [2] fd ea [2] ff eb [2] e4 ed [2] f8 ea [2] e4 c5 }

  condition:
    any of them
}