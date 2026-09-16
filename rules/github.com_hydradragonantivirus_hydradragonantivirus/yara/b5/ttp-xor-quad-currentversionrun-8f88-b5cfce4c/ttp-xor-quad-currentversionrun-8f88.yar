rule TTP_XOR_QUAD_CurrentVersionRun_8f88 {
  strings:
    $key_8f88 = { dc e7 [2] f8 e9 [2] d3 c5 [2] fd e7 [2] e9 fc [2] e6 e6 [2] f8 fb [2] fa fa [2] e1 fc [2] fd fb [2] e1 d4 }

  condition:
    any of them
}