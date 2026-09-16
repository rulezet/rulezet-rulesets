rule TTP_XOR_QUAD_CurrentVersionRun_4bbd {
  strings:
    $key_4bbd = { 18 d2 [2] 3c dc [2] 17 f0 [2] 39 d2 [2] 2d c9 [2] 22 d3 [2] 3c ce [2] 3e cf [2] 25 c9 [2] 39 ce [2] 25 e1 }

  condition:
    any of them
}