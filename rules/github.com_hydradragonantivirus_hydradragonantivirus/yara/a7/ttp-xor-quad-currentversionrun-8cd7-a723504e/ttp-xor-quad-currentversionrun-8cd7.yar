rule TTP_XOR_QUAD_CurrentVersionRun_8cd7 {
  strings:
    $key_8cd7 = { df b8 [2] fb b6 [2] d0 9a [2] fe b8 [2] ea a3 [2] e5 b9 [2] fb a4 [2] f9 a5 [2] e2 a3 [2] fe a4 [2] e2 8b }

  condition:
    any of them
}