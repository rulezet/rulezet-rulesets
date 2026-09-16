rule TTP_XOR_QUAD_CurrentVersionRun_f19c {
  strings:
    $key_f19c = { a2 f3 [2] 86 fd [2] ad d1 [2] 83 f3 [2] 97 e8 [2] 98 f2 [2] 86 ef [2] 84 ee [2] 9f e8 [2] 83 ef [2] 9f c0 }

  condition:
    any of them
}