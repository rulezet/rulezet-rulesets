rule TTP_XOR_QUAD_CurrentVersionRun_9388 {
  strings:
    $key_9388 = { c0 e7 [2] e4 e9 [2] cf c5 [2] e1 e7 [2] f5 fc [2] fa e6 [2] e4 fb [2] e6 fa [2] fd fc [2] e1 fb [2] fd d4 }

  condition:
    any of them
}