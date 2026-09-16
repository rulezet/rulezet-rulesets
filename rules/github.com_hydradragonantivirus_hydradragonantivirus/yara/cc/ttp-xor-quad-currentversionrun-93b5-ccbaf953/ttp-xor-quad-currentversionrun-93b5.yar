rule TTP_XOR_QUAD_CurrentVersionRun_93b5 {
  strings:
    $key_93b5 = { c0 da [2] e4 d4 [2] cf f8 [2] e1 da [2] f5 c1 [2] fa db [2] e4 c6 [2] e6 c7 [2] fd c1 [2] e1 c6 [2] fd e9 }

  condition:
    any of them
}