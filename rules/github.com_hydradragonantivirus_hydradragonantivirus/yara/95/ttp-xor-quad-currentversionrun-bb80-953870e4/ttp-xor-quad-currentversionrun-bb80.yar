rule TTP_XOR_QUAD_CurrentVersionRun_bb80 {
  strings:
    $key_bb80 = { e8 ef [2] cc e1 [2] e7 cd [2] c9 ef [2] dd f4 [2] d2 ee [2] cc f3 [2] ce f2 [2] d5 f4 [2] c9 f3 [2] d5 dc }

  condition:
    any of them
}