rule TTP_XOR_QUAD_CurrentVersionRun_fabd {
  strings:
    $key_fabd = { a9 d2 [2] 8d dc [2] a6 f0 [2] 88 d2 [2] 9c c9 [2] 93 d3 [2] 8d ce [2] 8f cf [2] 94 c9 [2] 88 ce [2] 94 e1 }

  condition:
    any of them
}