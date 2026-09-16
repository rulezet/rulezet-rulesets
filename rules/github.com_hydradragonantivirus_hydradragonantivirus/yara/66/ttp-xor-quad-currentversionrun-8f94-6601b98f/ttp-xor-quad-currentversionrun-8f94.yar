rule TTP_XOR_QUAD_CurrentVersionRun_8f94 {
  strings:
    $key_8f94 = { dc fb [2] f8 f5 [2] d3 d9 [2] fd fb [2] e9 e0 [2] e6 fa [2] f8 e7 [2] fa e6 [2] e1 e0 [2] fd e7 [2] e1 c8 }

  condition:
    any of them
}