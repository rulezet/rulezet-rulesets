rule TTP_XOR_QUAD_CurrentVersionRun_95f1 {
  strings:
    $key_95f1 = { c6 9e [2] e2 90 [2] c9 bc [2] e7 9e [2] f3 85 [2] fc 9f [2] e2 82 [2] e0 83 [2] fb 85 [2] e7 82 [2] fb ad }

  condition:
    any of them
}