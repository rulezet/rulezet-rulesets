rule TTP_XOR_QUAD_CurrentVersionRun_91a8 {
  strings:
    $key_91a8 = { c2 c7 [2] e6 c9 [2] cd e5 [2] e3 c7 [2] f7 dc [2] f8 c6 [2] e6 db [2] e4 da [2] ff dc [2] e3 db [2] ff f4 }

  condition:
    any of them
}