rule TTP_XOR_QUAD_CurrentVersionRun_91b4 {
  strings:
    $key_91b4 = { c2 db [2] e6 d5 [2] cd f9 [2] e3 db [2] f7 c0 [2] f8 da [2] e6 c7 [2] e4 c6 [2] ff c0 [2] e3 c7 [2] ff e8 }

  condition:
    any of them
}