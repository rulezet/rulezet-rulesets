rule TTP_XOR_QUAD_CurrentVersionRun_8443 {
  strings:
    $key_8443 = { d7 2c [2] f3 22 [2] d8 0e [2] f6 2c [2] e2 37 [2] ed 2d [2] f3 30 [2] f1 31 [2] ea 37 [2] f6 30 [2] ea 1f }

  condition:
    any of them
}