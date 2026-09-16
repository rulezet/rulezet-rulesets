rule TTP_XOR_QUAD_CurrentVersionRun_8c95 {
  strings:
    $key_8c95 = { df fa [2] fb f4 [2] d0 d8 [2] fe fa [2] ea e1 [2] e5 fb [2] fb e6 [2] f9 e7 [2] e2 e1 [2] fe e6 [2] e2 c9 }

  condition:
    any of them
}