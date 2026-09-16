rule TTP_XOR_QUAD_CurrentVersionRun_91a3 {
  strings:
    $key_91a3 = { c2 cc [2] e6 c2 [2] cd ee [2] e3 cc [2] f7 d7 [2] f8 cd [2] e6 d0 [2] e4 d1 [2] ff d7 [2] e3 d0 [2] ff ff }

  condition:
    any of them
}