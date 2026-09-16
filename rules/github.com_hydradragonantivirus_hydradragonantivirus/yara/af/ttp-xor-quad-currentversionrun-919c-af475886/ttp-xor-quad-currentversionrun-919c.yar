rule TTP_XOR_QUAD_CurrentVersionRun_919c {
  strings:
    $key_919c = { c2 f3 [2] e6 fd [2] cd d1 [2] e3 f3 [2] f7 e8 [2] f8 f2 [2] e6 ef [2] e4 ee [2] ff e8 [2] e3 ef [2] ff c0 }

  condition:
    any of them
}