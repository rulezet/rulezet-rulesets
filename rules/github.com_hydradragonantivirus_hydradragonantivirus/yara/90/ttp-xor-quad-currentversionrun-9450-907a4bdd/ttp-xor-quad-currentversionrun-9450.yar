rule TTP_XOR_QUAD_CurrentVersionRun_9450 {
  strings:
    $key_9450 = { c7 3f [2] e3 31 [2] c8 1d [2] e6 3f [2] f2 24 [2] fd 3e [2] e3 23 [2] e1 22 [2] fa 24 [2] e6 23 [2] fa 0c }

  condition:
    any of them
}