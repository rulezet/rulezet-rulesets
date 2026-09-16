rule TTP_XOR_QUAD_CurrentVersionRun_9aa6 {
  strings:
    $key_9aa6 = { c9 c9 [2] ed c7 [2] c6 eb [2] e8 c9 [2] fc d2 [2] f3 c8 [2] ed d5 [2] ef d4 [2] f4 d2 [2] e8 d5 [2] f4 fa }

  condition:
    any of them
}