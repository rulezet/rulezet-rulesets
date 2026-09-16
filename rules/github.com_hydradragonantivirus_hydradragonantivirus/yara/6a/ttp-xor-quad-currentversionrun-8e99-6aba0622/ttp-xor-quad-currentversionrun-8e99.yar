rule TTP_XOR_QUAD_CurrentVersionRun_8e99 {
  strings:
    $key_8e99 = { dd f6 [2] f9 f8 [2] d2 d4 [2] fc f6 [2] e8 ed [2] e7 f7 [2] f9 ea [2] fb eb [2] e0 ed [2] fc ea [2] e0 c5 }

  condition:
    any of them
}