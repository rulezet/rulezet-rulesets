rule TTP_XOR_QUAD_CurrentVersionRun_9287 {
  strings:
    $key_9287 = { c1 e8 [2] e5 e6 [2] ce ca [2] e0 e8 [2] f4 f3 [2] fb e9 [2] e5 f4 [2] e7 f5 [2] fc f3 [2] e0 f4 [2] fc db }

  condition:
    any of them
}