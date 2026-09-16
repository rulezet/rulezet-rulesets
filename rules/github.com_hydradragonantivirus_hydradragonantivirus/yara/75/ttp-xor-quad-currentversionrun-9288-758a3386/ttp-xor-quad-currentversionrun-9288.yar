rule TTP_XOR_QUAD_CurrentVersionRun_9288 {
  strings:
    $key_9288 = { c1 e7 [2] e5 e9 [2] ce c5 [2] e0 e7 [2] f4 fc [2] fb e6 [2] e5 fb [2] e7 fa [2] fc fc [2] e0 fb [2] fc d4 }

  condition:
    any of them
}