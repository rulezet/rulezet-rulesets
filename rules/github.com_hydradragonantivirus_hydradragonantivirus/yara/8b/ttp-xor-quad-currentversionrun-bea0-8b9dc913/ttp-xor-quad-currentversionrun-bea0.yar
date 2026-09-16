rule TTP_XOR_QUAD_CurrentVersionRun_bea0 {
  strings:
    $key_bea0 = { ed cf [2] c9 c1 [2] e2 ed [2] cc cf [2] d8 d4 [2] d7 ce [2] c9 d3 [2] cb d2 [2] d0 d4 [2] cc d3 [2] d0 fc }

  condition:
    any of them
}