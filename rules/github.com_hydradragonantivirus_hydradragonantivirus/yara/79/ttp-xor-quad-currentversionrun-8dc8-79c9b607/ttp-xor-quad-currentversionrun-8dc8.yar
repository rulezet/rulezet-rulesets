rule TTP_XOR_QUAD_CurrentVersionRun_8dc8 {
  strings:
    $key_8dc8 = { de a7 [2] fa a9 [2] d1 85 [2] ff a7 [2] eb bc [2] e4 a6 [2] fa bb [2] f8 ba [2] e3 bc [2] ff bb [2] e3 94 }

  condition:
    any of them
}