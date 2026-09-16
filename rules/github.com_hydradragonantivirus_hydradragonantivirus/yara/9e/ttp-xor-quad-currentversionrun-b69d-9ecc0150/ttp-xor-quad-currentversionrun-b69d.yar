rule TTP_XOR_QUAD_CurrentVersionRun_b69d {
  strings:
    $key_b69d = { e5 f2 [2] c1 fc [2] ea d0 [2] c4 f2 [2] d0 e9 [2] df f3 [2] c1 ee [2] c3 ef [2] d8 e9 [2] c4 ee [2] d8 c1 }

  condition:
    any of them
}