rule TTP_XOR_QUAD_CurrentVersionRun_8dd4 {
  strings:
    $key_8dd4 = { de bb [2] fa b5 [2] d1 99 [2] ff bb [2] eb a0 [2] e4 ba [2] fa a7 [2] f8 a6 [2] e3 a0 [2] ff a7 [2] e3 88 }

  condition:
    any of them
}