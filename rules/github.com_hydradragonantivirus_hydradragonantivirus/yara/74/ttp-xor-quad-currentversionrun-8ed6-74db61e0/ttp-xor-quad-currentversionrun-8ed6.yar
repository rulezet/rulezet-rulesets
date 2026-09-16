rule TTP_XOR_QUAD_CurrentVersionRun_8ed6 {
  strings:
    $key_8ed6 = { dd b9 [2] f9 b7 [2] d2 9b [2] fc b9 [2] e8 a2 [2] e7 b8 [2] f9 a5 [2] fb a4 [2] e0 a2 [2] fc a5 [2] e0 8a }

  condition:
    any of them
}