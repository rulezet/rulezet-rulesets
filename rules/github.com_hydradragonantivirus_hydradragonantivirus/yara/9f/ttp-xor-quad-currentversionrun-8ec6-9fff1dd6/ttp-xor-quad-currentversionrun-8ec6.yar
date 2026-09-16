rule TTP_XOR_QUAD_CurrentVersionRun_8ec6 {
  strings:
    $key_8ec6 = { dd a9 [2] f9 a7 [2] d2 8b [2] fc a9 [2] e8 b2 [2] e7 a8 [2] f9 b5 [2] fb b4 [2] e0 b2 [2] fc b5 [2] e0 9a }

  condition:
    any of them
}