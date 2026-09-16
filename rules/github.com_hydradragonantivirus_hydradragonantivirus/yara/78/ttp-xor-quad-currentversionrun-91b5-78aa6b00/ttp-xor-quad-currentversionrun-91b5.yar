rule TTP_XOR_QUAD_CurrentVersionRun_91b5 {
  strings:
    $key_91b5 = { c2 da [2] e6 d4 [2] cd f8 [2] e3 da [2] f7 c1 [2] f8 db [2] e6 c6 [2] e4 c7 [2] ff c1 [2] e3 c6 [2] ff e9 }

  condition:
    any of them
}