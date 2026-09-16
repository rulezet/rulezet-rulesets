rule TTP_XOR_QUAD_CurrentVersionRun_93c7 {
  strings:
    $key_93c7 = { c0 a8 [2] e4 a6 [2] cf 8a [2] e1 a8 [2] f5 b3 [2] fa a9 [2] e4 b4 [2] e6 b5 [2] fd b3 [2] e1 b4 [2] fd 9b }

  condition:
    any of them
}