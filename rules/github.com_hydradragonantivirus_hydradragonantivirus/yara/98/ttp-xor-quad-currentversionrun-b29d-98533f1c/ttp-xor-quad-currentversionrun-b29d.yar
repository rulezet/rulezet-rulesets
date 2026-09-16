rule TTP_XOR_QUAD_CurrentVersionRun_b29d {
  strings:
    $key_b29d = { e1 f2 [2] c5 fc [2] ee d0 [2] c0 f2 [2] d4 e9 [2] db f3 [2] c5 ee [2] c7 ef [2] dc e9 [2] c0 ee [2] dc c1 }

  condition:
    any of them
}