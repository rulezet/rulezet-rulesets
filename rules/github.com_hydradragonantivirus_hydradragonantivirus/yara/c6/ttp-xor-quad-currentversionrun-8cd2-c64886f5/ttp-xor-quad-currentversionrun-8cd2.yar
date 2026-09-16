rule TTP_XOR_QUAD_CurrentVersionRun_8cd2 {
  strings:
    $key_8cd2 = { df bd [2] fb b3 [2] d0 9f [2] fe bd [2] ea a6 [2] e5 bc [2] fb a1 [2] f9 a0 [2] e2 a6 [2] fe a1 [2] e2 8e }

  condition:
    any of them
}