rule TTP_XOR_QUAD_CurrentVersionRun_86e2 {
  strings:
    $key_86e2 = { d5 8d [2] f1 83 [2] da af [2] f4 8d [2] e0 96 [2] ef 8c [2] f1 91 [2] f3 90 [2] e8 96 [2] f4 91 [2] e8 be }

  condition:
    any of them
}