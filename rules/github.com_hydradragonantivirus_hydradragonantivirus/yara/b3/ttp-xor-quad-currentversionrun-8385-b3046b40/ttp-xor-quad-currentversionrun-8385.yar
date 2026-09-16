rule TTP_XOR_QUAD_CurrentVersionRun_8385 {
  strings:
    $key_8385 = { d0 ea [2] f4 e4 [2] df c8 [2] f1 ea [2] e5 f1 [2] ea eb [2] f4 f6 [2] f6 f7 [2] ed f1 [2] f1 f6 [2] ed d9 }

  condition:
    any of them
}