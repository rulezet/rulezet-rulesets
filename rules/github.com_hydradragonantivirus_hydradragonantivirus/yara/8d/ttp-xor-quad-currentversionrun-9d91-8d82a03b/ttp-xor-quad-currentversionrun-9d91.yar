rule TTP_XOR_QUAD_CurrentVersionRun_9d91 {
  strings:
    $key_9d91 = { ce fe [2] ea f0 [2] c1 dc [2] ef fe [2] fb e5 [2] f4 ff [2] ea e2 [2] e8 e3 [2] f3 e5 [2] ef e2 [2] f3 cd }

  condition:
    any of them
}