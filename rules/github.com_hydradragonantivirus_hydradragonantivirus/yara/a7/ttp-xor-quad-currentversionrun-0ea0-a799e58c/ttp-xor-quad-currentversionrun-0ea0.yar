rule TTP_XOR_QUAD_CurrentVersionRun_0ea0 {
  strings:
    $key_0ea0 = { 5d cf [2] 79 c1 [2] 52 ed [2] 7c cf [2] 68 d4 [2] 67 ce [2] 79 d3 [2] 7b d2 [2] 60 d4 [2] 7c d3 [2] 60 fc }

  condition:
    any of them
}