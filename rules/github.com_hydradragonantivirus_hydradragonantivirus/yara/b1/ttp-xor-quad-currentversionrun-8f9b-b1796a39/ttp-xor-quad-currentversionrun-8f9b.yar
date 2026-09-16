rule TTP_XOR_QUAD_CurrentVersionRun_8f9b {
  strings:
    $key_8f9b = { dc f4 [2] f8 fa [2] d3 d6 [2] fd f4 [2] e9 ef [2] e6 f5 [2] f8 e8 [2] fa e9 [2] e1 ef [2] fd e8 [2] e1 c7 }

  condition:
    any of them
}