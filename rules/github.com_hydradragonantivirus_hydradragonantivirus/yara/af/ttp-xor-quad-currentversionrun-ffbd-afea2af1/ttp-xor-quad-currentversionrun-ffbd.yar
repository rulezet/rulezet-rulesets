rule TTP_XOR_QUAD_CurrentVersionRun_ffbd {
  strings:
    $key_ffbd = { ac d2 [2] 88 dc [2] a3 f0 [2] 8d d2 [2] 99 c9 [2] 96 d3 [2] 88 ce [2] 8a cf [2] 91 c9 [2] 8d ce [2] 91 e1 }

  condition:
    any of them
}