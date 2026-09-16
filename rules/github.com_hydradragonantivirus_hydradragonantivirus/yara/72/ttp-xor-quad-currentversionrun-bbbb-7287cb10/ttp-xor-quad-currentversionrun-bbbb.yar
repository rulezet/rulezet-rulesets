rule TTP_XOR_QUAD_CurrentVersionRun_bbbb {
  strings:
    $key_bbbb = { e8 d4 [2] cc da [2] e7 f6 [2] c9 d4 [2] dd cf [2] d2 d5 [2] cc c8 [2] ce c9 [2] d5 cf [2] c9 c8 [2] d5 e7 }

  condition:
    any of them
}