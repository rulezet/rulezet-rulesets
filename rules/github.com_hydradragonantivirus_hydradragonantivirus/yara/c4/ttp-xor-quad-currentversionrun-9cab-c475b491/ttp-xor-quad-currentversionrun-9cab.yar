rule TTP_XOR_QUAD_CurrentVersionRun_9cab {
  strings:
    $key_9cab = { cf c4 [2] eb ca [2] c0 e6 [2] ee c4 [2] fa df [2] f5 c5 [2] eb d8 [2] e9 d9 [2] f2 df [2] ee d8 [2] f2 f7 }

  condition:
    any of them
}