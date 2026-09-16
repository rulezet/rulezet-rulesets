rule TTP_XOR_QUAD_CurrentVersionRun_8ed7 {
  strings:
    $key_8ed7 = { dd b8 [2] f9 b6 [2] d2 9a [2] fc b8 [2] e8 a3 [2] e7 b9 [2] f9 a4 [2] fb a5 [2] e0 a3 [2] fc a4 [2] e0 8b }

  condition:
    any of them
}