rule TTP_XOR_QUAD_CurrentVersionRun_9c87 {
  strings:
    $key_9c87 = { cf e8 [2] eb e6 [2] c0 ca [2] ee e8 [2] fa f3 [2] f5 e9 [2] eb f4 [2] e9 f5 [2] f2 f3 [2] ee f4 [2] f2 db }

  condition:
    any of them
}