rule TTP_XOR_QUAD_CurrentVersionRun_9c80 {
  strings:
    $key_9c80 = { cf ef [2] eb e1 [2] c0 cd [2] ee ef [2] fa f4 [2] f5 ee [2] eb f3 [2] e9 f2 [2] f2 f4 [2] ee f3 [2] f2 dc }

  condition:
    any of them
}