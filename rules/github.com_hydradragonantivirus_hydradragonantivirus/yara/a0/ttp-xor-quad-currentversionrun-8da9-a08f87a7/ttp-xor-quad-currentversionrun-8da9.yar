rule TTP_XOR_QUAD_CurrentVersionRun_8da9 {
  strings:
    $key_8da9 = { de c6 [2] fa c8 [2] d1 e4 [2] ff c6 [2] eb dd [2] e4 c7 [2] fa da [2] f8 db [2] e3 dd [2] ff da [2] e3 f5 }

  condition:
    any of them
}