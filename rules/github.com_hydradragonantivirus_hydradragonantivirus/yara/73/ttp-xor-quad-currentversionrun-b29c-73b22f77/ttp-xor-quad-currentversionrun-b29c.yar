rule TTP_XOR_QUAD_CurrentVersionRun_b29c {
  strings:
    $key_b29c = { e1 f3 [2] c5 fd [2] ee d1 [2] c0 f3 [2] d4 e8 [2] db f2 [2] c5 ef [2] c7 ee [2] dc e8 [2] c0 ef [2] dc c0 }

  condition:
    any of them
}