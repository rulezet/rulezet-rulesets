rule TTP_XOR_QUAD_CurrentVersionRun_9386 {
  strings:
    $key_9386 = { c0 e9 [2] e4 e7 [2] cf cb [2] e1 e9 [2] f5 f2 [2] fa e8 [2] e4 f5 [2] e6 f4 [2] fd f2 [2] e1 f5 [2] fd da }

  condition:
    any of them
}