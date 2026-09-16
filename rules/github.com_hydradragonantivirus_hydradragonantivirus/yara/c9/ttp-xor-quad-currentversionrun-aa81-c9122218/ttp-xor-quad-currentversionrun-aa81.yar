rule TTP_XOR_QUAD_CurrentVersionRun_aa81 {
  strings:
    $key_aa81 = { f9 ee [2] dd e0 [2] f6 cc [2] d8 ee [2] cc f5 [2] c3 ef [2] dd f2 [2] df f3 [2] c4 f5 [2] d8 f2 [2] c4 dd }

  condition:
    any of them
}