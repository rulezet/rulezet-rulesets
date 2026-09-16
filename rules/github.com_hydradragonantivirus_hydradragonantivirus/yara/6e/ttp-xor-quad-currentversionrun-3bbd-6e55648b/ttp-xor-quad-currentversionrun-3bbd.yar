rule TTP_XOR_QUAD_CurrentVersionRun_3bbd {
  strings:
    $key_3bbd = { 68 d2 [2] 4c dc [2] 67 f0 [2] 49 d2 [2] 5d c9 [2] 52 d3 [2] 4c ce [2] 4e cf [2] 55 c9 [2] 49 ce [2] 55 e1 }

  condition:
    any of them
}