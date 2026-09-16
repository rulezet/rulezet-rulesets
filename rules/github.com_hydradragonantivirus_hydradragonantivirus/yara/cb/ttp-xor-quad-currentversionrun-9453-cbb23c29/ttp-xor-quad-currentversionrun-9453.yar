rule TTP_XOR_QUAD_CurrentVersionRun_9453 {
  strings:
    $key_9453 = { c7 3c [2] e3 32 [2] c8 1e [2] e6 3c [2] f2 27 [2] fd 3d [2] e3 20 [2] e1 21 [2] fa 27 [2] e6 20 [2] fa 0f }

  condition:
    any of them
}