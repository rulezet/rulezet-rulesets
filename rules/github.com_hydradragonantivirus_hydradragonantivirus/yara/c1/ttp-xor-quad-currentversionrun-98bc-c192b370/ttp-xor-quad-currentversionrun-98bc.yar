rule TTP_XOR_QUAD_CurrentVersionRun_98bc {
  strings:
    $key_98bc = { cb d3 [2] ef dd [2] c4 f1 [2] ea d3 [2] fe c8 [2] f1 d2 [2] ef cf [2] ed ce [2] f6 c8 [2] ea cf [2] f6 e0 }

  condition:
    any of them
}