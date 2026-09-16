rule TTP_XOR_QUAD_CurrentVersionRun_f1a0 {
  strings:
    $key_f1a0 = { a2 cf [2] 86 c1 [2] ad ed [2] 83 cf [2] 97 d4 [2] 98 ce [2] 86 d3 [2] 84 d2 [2] 9f d4 [2] 83 d3 [2] 9f fc }

  condition:
    any of them
}