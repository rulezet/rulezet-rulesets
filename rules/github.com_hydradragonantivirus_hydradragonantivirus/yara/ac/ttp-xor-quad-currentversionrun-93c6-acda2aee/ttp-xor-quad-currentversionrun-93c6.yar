rule TTP_XOR_QUAD_CurrentVersionRun_93c6 {
  strings:
    $key_93c6 = { c0 a9 [2] e4 a7 [2] cf 8b [2] e1 a9 [2] f5 b2 [2] fa a8 [2] e4 b5 [2] e6 b4 [2] fd b2 [2] e1 b5 [2] fd 9a }

  condition:
    any of them
}