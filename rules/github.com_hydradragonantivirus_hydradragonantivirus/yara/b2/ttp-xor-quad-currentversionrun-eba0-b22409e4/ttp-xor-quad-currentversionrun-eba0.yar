rule TTP_XOR_QUAD_CurrentVersionRun_eba0 {
  strings:
    $key_eba0 = { b8 cf [2] 9c c1 [2] b7 ed [2] 99 cf [2] 8d d4 [2] 82 ce [2] 9c d3 [2] 9e d2 [2] 85 d4 [2] 99 d3 [2] 85 fc }

  condition:
    any of them
}