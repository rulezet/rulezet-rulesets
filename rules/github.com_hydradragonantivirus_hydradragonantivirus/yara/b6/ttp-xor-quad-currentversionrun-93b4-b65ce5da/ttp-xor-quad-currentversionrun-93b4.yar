rule TTP_XOR_QUAD_CurrentVersionRun_93b4 {
  strings:
    $key_93b4 = { c0 db [2] e4 d5 [2] cf f9 [2] e1 db [2] f5 c0 [2] fa da [2] e4 c7 [2] e6 c6 [2] fd c0 [2] e1 c7 [2] fd e8 }

  condition:
    any of them
}