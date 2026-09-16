rule TTP_XOR_QUAD_CurrentVersionRun_8f95 {
  strings:
    $key_8f95 = { dc fa [2] f8 f4 [2] d3 d8 [2] fd fa [2] e9 e1 [2] e6 fb [2] f8 e6 [2] fa e7 [2] e1 e1 [2] fd e6 [2] e1 c9 }

  condition:
    any of them
}