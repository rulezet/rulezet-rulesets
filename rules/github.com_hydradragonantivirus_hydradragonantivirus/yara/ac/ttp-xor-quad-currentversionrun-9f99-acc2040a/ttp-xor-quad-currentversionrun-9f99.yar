rule TTP_XOR_QUAD_CurrentVersionRun_9f99 {
  strings:
    $key_9f99 = { cc f6 [2] e8 f8 [2] c3 d4 [2] ed f6 [2] f9 ed [2] f6 f7 [2] e8 ea [2] ea eb [2] f1 ed [2] ed ea [2] f1 c5 }

  condition:
    any of them
}