rule TTP_XOR_QUAD_CurrentVersionRun_8dd6 {
  strings:
    $key_8dd6 = { de b9 [2] fa b7 [2] d1 9b [2] ff b9 [2] eb a2 [2] e4 b8 [2] fa a5 [2] f8 a4 [2] e3 a2 [2] ff a5 [2] e3 8a }

  condition:
    any of them
}