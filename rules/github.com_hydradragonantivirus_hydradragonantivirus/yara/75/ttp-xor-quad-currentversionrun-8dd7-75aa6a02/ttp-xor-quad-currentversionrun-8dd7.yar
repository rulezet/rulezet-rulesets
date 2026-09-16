rule TTP_XOR_QUAD_CurrentVersionRun_8dd7 {
  strings:
    $key_8dd7 = { de b8 [2] fa b6 [2] d1 9a [2] ff b8 [2] eb a3 [2] e4 b9 [2] fa a4 [2] f8 a5 [2] e3 a3 [2] ff a4 [2] e3 8b }

  condition:
    any of them
}