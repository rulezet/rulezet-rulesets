rule TTP_XOR_QUAD_CurrentVersionRun_95f6 {
  strings:
    $key_95f6 = { c6 99 [2] e2 97 [2] c9 bb [2] e7 99 [2] f3 82 [2] fc 98 [2] e2 85 [2] e0 84 [2] fb 82 [2] e7 85 [2] fb aa }

  condition:
    any of them
}