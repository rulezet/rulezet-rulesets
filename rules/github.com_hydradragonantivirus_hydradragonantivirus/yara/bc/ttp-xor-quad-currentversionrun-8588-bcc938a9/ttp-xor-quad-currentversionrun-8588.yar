rule TTP_XOR_QUAD_CurrentVersionRun_8588 {
  strings:
    $key_8588 = { d6 e7 [2] f2 e9 [2] d9 c5 [2] f7 e7 [2] e3 fc [2] ec e6 [2] f2 fb [2] f0 fa [2] eb fc [2] f7 fb [2] eb d4 }

  condition:
    any of them
}