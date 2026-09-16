rule TTP_XOR_QUAD_CurrentVersionRun_95f0 {
  strings:
    $key_95f0 = { c6 9f [2] e2 91 [2] c9 bd [2] e7 9f [2] f3 84 [2] fc 9e [2] e2 83 [2] e0 82 [2] fb 84 [2] e7 83 [2] fb ac }

  condition:
    any of them
}