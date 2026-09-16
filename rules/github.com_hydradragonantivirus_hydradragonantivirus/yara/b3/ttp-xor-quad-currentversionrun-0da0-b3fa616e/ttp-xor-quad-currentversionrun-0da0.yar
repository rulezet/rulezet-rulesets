rule TTP_XOR_QUAD_CurrentVersionRun_0da0 {
  strings:
    $key_0da0 = { 5e cf [2] 7a c1 [2] 51 ed [2] 7f cf [2] 6b d4 [2] 64 ce [2] 7a d3 [2] 78 d2 [2] 63 d4 [2] 7f d3 [2] 63 fc }

  condition:
    any of them
}