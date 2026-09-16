rule TTP_XOR_QUAD_CurrentVersionRun_91a9 {
  strings:
    $key_91a9 = { c2 c6 [2] e6 c8 [2] cd e4 [2] e3 c6 [2] f7 dd [2] f8 c7 [2] e6 da [2] e4 db [2] ff dd [2] e3 da [2] ff f5 }

  condition:
    any of them
}