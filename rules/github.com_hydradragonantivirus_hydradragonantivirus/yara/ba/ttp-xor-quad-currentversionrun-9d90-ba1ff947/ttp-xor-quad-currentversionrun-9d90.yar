rule TTP_XOR_QUAD_CurrentVersionRun_9d90 {
  strings:
    $key_9d90 = { ce ff [2] ea f1 [2] c1 dd [2] ef ff [2] fb e4 [2] f4 fe [2] ea e3 [2] e8 e2 [2] f3 e4 [2] ef e3 [2] f3 cc }

  condition:
    any of them
}