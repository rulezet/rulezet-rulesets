rule TTP_XOR_QUAD_CurrentVersionRun_8db5 {
  strings:
    $key_8db5 = { de da [2] fa d4 [2] d1 f8 [2] ff da [2] eb c1 [2] e4 db [2] fa c6 [2] f8 c7 [2] e3 c1 [2] ff c6 [2] e3 e9 }

  condition:
    any of them
}