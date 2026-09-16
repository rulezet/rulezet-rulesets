rule TTP_XOR_QUAD_CurrentVersionRun_86a2 {
  strings:
    $key_86a2 = { d5 cd [2] f1 c3 [2] da ef [2] f4 cd [2] e0 d6 [2] ef cc [2] f1 d1 [2] f3 d0 [2] e8 d6 [2] f4 d1 [2] e8 fe }

  condition:
    any of them
}