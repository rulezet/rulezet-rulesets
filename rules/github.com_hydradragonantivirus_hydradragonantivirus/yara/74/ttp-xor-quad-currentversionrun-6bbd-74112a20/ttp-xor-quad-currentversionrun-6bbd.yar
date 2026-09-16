rule TTP_XOR_QUAD_CurrentVersionRun_6bbd {
  strings:
    $key_6bbd = { 38 d2 [2] 1c dc [2] 37 f0 [2] 19 d2 [2] 0d c9 [2] 02 d3 [2] 1c ce [2] 1e cf [2] 05 c9 [2] 19 ce [2] 05 e1 }

  condition:
    any of them
}