rule TTP_XOR_QUAD_CurrentVersionRun_93a6 {
  strings:
    $key_93a6 = { c0 c9 [2] e4 c7 [2] cf eb [2] e1 c9 [2] f5 d2 [2] fa c8 [2] e4 d5 [2] e6 d4 [2] fd d2 [2] e1 d5 [2] fd fa }

  condition:
    any of them
}