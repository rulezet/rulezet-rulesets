rule TTP_XOR_QUAD_CurrentVersionRun_8cd0 {
  strings:
    $key_8cd0 = { df bf [2] fb b1 [2] d0 9d [2] fe bf [2] ea a4 [2] e5 be [2] fb a3 [2] f9 a2 [2] e2 a4 [2] fe a3 [2] e2 8c }

  condition:
    any of them
}