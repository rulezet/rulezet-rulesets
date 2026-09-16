rule TTP_XOR_QUAD_CurrentVersionRun_91b3 {
  strings:
    $key_91b3 = { c2 dc [2] e6 d2 [2] cd fe [2] e3 dc [2] f7 c7 [2] f8 dd [2] e6 c0 [2] e4 c1 [2] ff c7 [2] e3 c0 [2] ff ef }

  condition:
    any of them
}