rule TTP_XOR_QUAD_CurrentVersionRun_8e94 {
  strings:
    $key_8e94 = { dd fb [2] f9 f5 [2] d2 d9 [2] fc fb [2] e8 e0 [2] e7 fa [2] f9 e7 [2] fb e6 [2] e0 e0 [2] fc e7 [2] e0 c8 }

  condition:
    any of them
}