rule TTP_XOR_QUAD_CurrentVersionRun_9416 {
  strings:
    $key_9416 = { c7 79 [2] e3 77 [2] c8 5b [2] e6 79 [2] f2 62 [2] fd 78 [2] e3 65 [2] e1 64 [2] fa 62 [2] e6 65 [2] fa 4a }

  condition:
    any of them
}