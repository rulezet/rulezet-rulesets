rule TTP_XOR_QUAD_CurrentVersionRun_91bd {
  strings:
    $key_91bd = { c2 d2 [2] e6 dc [2] cd f0 [2] e3 d2 [2] f7 c9 [2] f8 d3 [2] e6 ce [2] e4 cf [2] ff c9 [2] e3 ce [2] ff e1 }

  condition:
    any of them
}