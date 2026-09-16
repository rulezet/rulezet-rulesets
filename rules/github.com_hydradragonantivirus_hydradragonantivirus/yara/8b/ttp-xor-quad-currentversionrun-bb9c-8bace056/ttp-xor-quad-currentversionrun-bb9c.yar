rule TTP_XOR_QUAD_CurrentVersionRun_bb9c {
  strings:
    $key_bb9c = { e8 f3 [2] cc fd [2] e7 d1 [2] c9 f3 [2] dd e8 [2] d2 f2 [2] cc ef [2] ce ee [2] d5 e8 [2] c9 ef [2] d5 c0 }

  condition:
    any of them
}