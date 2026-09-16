rule TTP_XOR_QUAD_CurrentVersionRun_9ca3 {
  strings:
    $key_9ca3 = { cf cc [2] eb c2 [2] c0 ee [2] ee cc [2] fa d7 [2] f5 cd [2] eb d0 [2] e9 d1 [2] f2 d7 [2] ee d0 [2] f2 ff }

  condition:
    any of them
}