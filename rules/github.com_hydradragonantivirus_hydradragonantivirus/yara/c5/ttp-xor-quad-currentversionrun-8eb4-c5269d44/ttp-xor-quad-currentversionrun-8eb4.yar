rule TTP_XOR_QUAD_CurrentVersionRun_8eb4 {
  strings:
    $key_8eb4 = { dd db [2] f9 d5 [2] d2 f9 [2] fc db [2] e8 c0 [2] e7 da [2] f9 c7 [2] fb c6 [2] e0 c0 [2] fc c7 [2] e0 e8 }

  condition:
    any of them
}