rule TTP_XOR_QUAD_CurrentVersionRun_b9a0 {
  strings:
    $key_b9a0 = { ea cf [2] ce c1 [2] e5 ed [2] cb cf [2] df d4 [2] d0 ce [2] ce d3 [2] cc d2 [2] d7 d4 [2] cb d3 [2] d7 fc }

  condition:
    any of them
}