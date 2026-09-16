rule TTP_XOR_QUAD_CurrentVersionRun_8cd4 {
  strings:
    $key_8cd4 = { df bb [2] fb b5 [2] d0 99 [2] fe bb [2] ea a0 [2] e5 ba [2] fb a7 [2] f9 a6 [2] e2 a0 [2] fe a7 [2] e2 88 }

  condition:
    any of them
}