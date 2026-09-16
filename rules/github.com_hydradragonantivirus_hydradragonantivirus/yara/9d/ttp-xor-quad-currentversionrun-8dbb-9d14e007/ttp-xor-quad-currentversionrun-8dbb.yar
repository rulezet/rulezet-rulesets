rule TTP_XOR_QUAD_CurrentVersionRun_8dbb {
  strings:
    $key_8dbb = { de d4 [2] fa da [2] d1 f6 [2] ff d4 [2] eb cf [2] e4 d5 [2] fa c8 [2] f8 c9 [2] e3 cf [2] ff c8 [2] e3 e7 }

  condition:
    any of them
}