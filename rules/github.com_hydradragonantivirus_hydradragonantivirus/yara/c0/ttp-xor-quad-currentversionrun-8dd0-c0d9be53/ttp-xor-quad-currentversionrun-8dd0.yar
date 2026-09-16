rule TTP_XOR_QUAD_CurrentVersionRun_8dd0 {
  strings:
    $key_8dd0 = { de bf [2] fa b1 [2] d1 9d [2] ff bf [2] eb a4 [2] e4 be [2] fa a3 [2] f8 a2 [2] e3 a4 [2] ff a3 [2] e3 8c }

  condition:
    any of them
}