rule TTP_XOR_QUAD_CurrentVersionRun_8584 {
  strings:
    $key_8584 = { d6 eb [2] f2 e5 [2] d9 c9 [2] f7 eb [2] e3 f0 [2] ec ea [2] f2 f7 [2] f0 f6 [2] eb f0 [2] f7 f7 [2] eb d8 }

  condition:
    any of them
}