rule TTP_XOR_QUAD_CurrentVersionRun_9699 {
  strings:
    $key_9699 = { c5 f6 [2] e1 f8 [2] ca d4 [2] e4 f6 [2] f0 ed [2] ff f7 [2] e1 ea [2] e3 eb [2] f8 ed [2] e4 ea [2] f8 c5 }

  condition:
    any of them
}