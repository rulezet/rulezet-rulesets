rule TTP_XOR_QUAD_CurrentVersionRun_8eb5 {
  strings:
    $key_8eb5 = { dd da [2] f9 d4 [2] d2 f8 [2] fc da [2] e8 c1 [2] e7 db [2] f9 c6 [2] fb c7 [2] e0 c1 [2] fc c6 [2] e0 e9 }

  condition:
    any of them
}