rule TTP_XOR_QUAD_CurrentVersionRun_939b {
  strings:
    $key_939b = { c0 f4 [2] e4 fa [2] cf d6 [2] e1 f4 [2] f5 ef [2] fa f5 [2] e4 e8 [2] e6 e9 [2] fd ef [2] e1 e8 [2] fd c7 }

  condition:
    any of them
}