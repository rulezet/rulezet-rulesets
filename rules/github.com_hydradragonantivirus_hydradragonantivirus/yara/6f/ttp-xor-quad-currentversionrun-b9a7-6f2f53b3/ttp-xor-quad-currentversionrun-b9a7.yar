rule TTP_XOR_QUAD_CurrentVersionRun_b9a7 {
  strings:
    $key_b9a7 = { ea c8 [2] ce c6 [2] e5 ea [2] cb c8 [2] df d3 [2] d0 c9 [2] ce d4 [2] cc d5 [2] d7 d3 [2] cb d4 [2] d7 fb }

  condition:
    any of them
}