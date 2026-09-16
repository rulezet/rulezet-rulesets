rule TTP_XOR_QUAD_CurrentVersionRun_94e2 {
  strings:
    $key_94e2 = { c7 8d [2] e3 83 [2] c8 af [2] e6 8d [2] f2 96 [2] fd 8c [2] e3 91 [2] e1 90 [2] fa 96 [2] e6 91 [2] fa be }

  condition:
    any of them
}