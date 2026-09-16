rule TTP_XOR_QUAD_CurrentVersionRun_9d93 {
  strings:
    $key_9d93 = { ce fc [2] ea f2 [2] c1 de [2] ef fc [2] fb e7 [2] f4 fd [2] ea e0 [2] e8 e1 [2] f3 e7 [2] ef e0 [2] f3 cf }

  condition:
    any of them
}