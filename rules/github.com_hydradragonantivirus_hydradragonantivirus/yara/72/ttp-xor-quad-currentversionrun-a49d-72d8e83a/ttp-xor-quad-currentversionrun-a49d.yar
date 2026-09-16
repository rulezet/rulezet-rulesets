rule TTP_XOR_QUAD_CurrentVersionRun_a49d {
  strings:
    $key_a49d = { f7 f2 [2] d3 fc [2] f8 d0 [2] d6 f2 [2] c2 e9 [2] cd f3 [2] d3 ee [2] d1 ef [2] ca e9 [2] d6 ee [2] ca c1 }

  condition:
    any of them
}