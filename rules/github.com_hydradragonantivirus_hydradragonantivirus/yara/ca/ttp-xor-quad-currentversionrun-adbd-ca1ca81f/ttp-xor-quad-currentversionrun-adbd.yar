rule TTP_XOR_QUAD_CurrentVersionRun_adbd {
  strings:
    $key_adbd = { fe d2 [2] da dc [2] f1 f0 [2] df d2 [2] cb c9 [2] c4 d3 [2] da ce [2] d8 cf [2] c3 c9 [2] df ce [2] c3 e1 }

  condition:
    any of them
}