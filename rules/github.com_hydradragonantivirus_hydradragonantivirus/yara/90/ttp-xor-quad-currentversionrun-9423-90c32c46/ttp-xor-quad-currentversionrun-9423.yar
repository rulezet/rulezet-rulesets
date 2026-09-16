rule TTP_XOR_QUAD_CurrentVersionRun_9423 {
  strings:
    $key_9423 = { c7 4c [2] e3 42 [2] c8 6e [2] e6 4c [2] f2 57 [2] fd 4d [2] e3 50 [2] e1 51 [2] fa 57 [2] e6 50 [2] fa 7f }

  condition:
    any of them
}