rule TTP_XOR_QUAD_CurrentVersionRun_faa0 {
  strings:
    $key_faa0 = { a9 cf [2] 8d c1 [2] a6 ed [2] 88 cf [2] 9c d4 [2] 93 ce [2] 8d d3 [2] 8f d2 [2] 94 d4 [2] 88 d3 [2] 94 fc }

  condition:
    any of them
}