rule TTP_XOR_QUAD_CurrentVersionRun_9a98 {
  strings:
    $key_9a98 = { c9 f7 [2] ed f9 [2] c6 d5 [2] e8 f7 [2] fc ec [2] f3 f6 [2] ed eb [2] ef ea [2] f4 ec [2] e8 eb [2] f4 c4 }

  condition:
    any of them
}