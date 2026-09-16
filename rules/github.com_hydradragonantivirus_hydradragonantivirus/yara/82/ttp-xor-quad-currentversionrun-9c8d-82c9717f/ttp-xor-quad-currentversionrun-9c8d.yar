rule TTP_XOR_QUAD_CurrentVersionRun_9c8d {
  strings:
    $key_9c8d = { cf e2 [2] eb ec [2] c0 c0 [2] ee e2 [2] fa f9 [2] f5 e3 [2] eb fe [2] e9 ff [2] f2 f9 [2] ee fe [2] f2 d1 }

  condition:
    any of them
}