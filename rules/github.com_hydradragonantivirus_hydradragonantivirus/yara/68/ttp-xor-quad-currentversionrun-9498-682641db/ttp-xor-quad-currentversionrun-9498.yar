rule TTP_XOR_QUAD_CurrentVersionRun_9498 {
  strings:
    $key_9498 = { c7 f7 [2] e3 f9 [2] c8 d5 [2] e6 f7 [2] f2 ec [2] fd f6 [2] e3 eb [2] e1 ea [2] fa ec [2] e6 eb [2] fa c4 }

  condition:
    any of them
}