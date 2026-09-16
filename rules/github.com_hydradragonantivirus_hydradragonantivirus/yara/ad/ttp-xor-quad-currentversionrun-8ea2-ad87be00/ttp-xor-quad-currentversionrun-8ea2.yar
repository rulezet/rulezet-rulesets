rule TTP_XOR_QUAD_CurrentVersionRun_8ea2 {
  strings:
    $key_8ea2 = { dd cd [2] f9 c3 [2] d2 ef [2] fc cd [2] e8 d6 [2] e7 cc [2] f9 d1 [2] fb d0 [2] e0 d6 [2] fc d1 [2] e0 fe }

  condition:
    any of them
}