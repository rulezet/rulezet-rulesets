rule TTP_XOR_QUAD_CurrentVersionRun_8cf7 {
  strings:
    $key_8cf7 = { df 98 [2] fb 96 [2] d0 ba [2] fe 98 [2] ea 83 [2] e5 99 [2] fb 84 [2] f9 85 [2] e2 83 [2] fe 84 [2] e2 ab }

  condition:
    any of them
}