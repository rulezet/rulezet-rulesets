rule TTP_XOR_QUAD_CurrentVersionRun_eabd {
  strings:
    $key_eabd = { b9 d2 [2] 9d dc [2] b6 f0 [2] 98 d2 [2] 8c c9 [2] 83 d3 [2] 9d ce [2] 9f cf [2] 84 c9 [2] 98 ce [2] 84 e1 }

  condition:
    any of them
}