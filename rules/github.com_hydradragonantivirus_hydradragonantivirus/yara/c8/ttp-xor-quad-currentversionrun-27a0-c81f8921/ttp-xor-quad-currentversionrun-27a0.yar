rule TTP_XOR_QUAD_CurrentVersionRun_27a0 {
  strings:
    $key_27a0 = { 74 cf [2] 50 c1 [2] 7b ed [2] 55 cf [2] 41 d4 [2] 4e ce [2] 50 d3 [2] 52 d2 [2] 49 d4 [2] 55 d3 [2] 49 fc }

  condition:
    any of them
}