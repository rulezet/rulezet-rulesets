rule TTP_XOR_QUAD_CurrentVersionRun_dbbd {
  strings:
    $key_dbbd = { 88 d2 [2] ac dc [2] 87 f0 [2] a9 d2 [2] bd c9 [2] b2 d3 [2] ac ce [2] ae cf [2] b5 c9 [2] a9 ce [2] b5 e1 }

  condition:
    any of them
}