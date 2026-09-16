rule TTP_XOR_QUAD_CurrentVersionRun_a490 {
  strings:
    $key_a490 = { f7 ff [2] d3 f1 [2] f8 dd [2] d6 ff [2] c2 e4 [2] cd fe [2] d3 e3 [2] d1 e2 [2] ca e4 [2] d6 e3 [2] ca cc }

  condition:
    any of them
}