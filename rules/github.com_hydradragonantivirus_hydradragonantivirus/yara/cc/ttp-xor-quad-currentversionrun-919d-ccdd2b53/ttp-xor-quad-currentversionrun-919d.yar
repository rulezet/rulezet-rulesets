rule TTP_XOR_QUAD_CurrentVersionRun_919d {
  strings:
    $key_919d = { c2 f2 [2] e6 fc [2] cd d0 [2] e3 f2 [2] f7 e9 [2] f8 f3 [2] e6 ee [2] e4 ef [2] ff e9 [2] e3 ee [2] ff c1 }

  condition:
    any of them
}