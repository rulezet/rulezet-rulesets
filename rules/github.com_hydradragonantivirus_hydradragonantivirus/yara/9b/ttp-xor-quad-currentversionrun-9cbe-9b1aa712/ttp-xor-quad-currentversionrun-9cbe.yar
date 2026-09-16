rule TTP_XOR_QUAD_CurrentVersionRun_9cbe {
  strings:
    $key_9cbe = { cf d1 [2] eb df [2] c0 f3 [2] ee d1 [2] fa ca [2] f5 d0 [2] eb cd [2] e9 cc [2] f2 ca [2] ee cd [2] f2 e2 }

  condition:
    any of them
}