rule TTP_XOR_QUAD_CurrentVersionRun_8da6 {
  strings:
    $key_8da6 = { de c9 [2] fa c7 [2] d1 eb [2] ff c9 [2] eb d2 [2] e4 c8 [2] fa d5 [2] f8 d4 [2] e3 d2 [2] ff d5 [2] e3 fa }

  condition:
    any of them
}