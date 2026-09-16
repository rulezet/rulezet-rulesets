rule TTP_XOR_QUAD_CurrentVersionRun_9491 {
  strings:
    $key_9491 = { c7 fe [2] e3 f0 [2] c8 dc [2] e6 fe [2] f2 e5 [2] fd ff [2] e3 e2 [2] e1 e3 [2] fa e5 [2] e6 e2 [2] fa cd }

  condition:
    any of them
}