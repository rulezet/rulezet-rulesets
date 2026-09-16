rule TTP_XOR_QUAD_CurrentVersionRun_b9a6 {
  strings:
    $key_b9a6 = { ea c9 [2] ce c7 [2] e5 eb [2] cb c9 [2] df d2 [2] d0 c8 [2] ce d5 [2] cc d4 [2] d7 d2 [2] cb d5 [2] d7 fa }

  condition:
    any of them
}