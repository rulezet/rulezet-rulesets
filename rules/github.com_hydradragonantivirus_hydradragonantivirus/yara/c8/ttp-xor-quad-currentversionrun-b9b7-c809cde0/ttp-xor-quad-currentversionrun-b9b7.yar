rule TTP_XOR_QUAD_CurrentVersionRun_b9b7 {
  strings:
    $key_b9b7 = { ea d8 [2] ce d6 [2] e5 fa [2] cb d8 [2] df c3 [2] d0 d9 [2] ce c4 [2] cc c5 [2] d7 c3 [2] cb c4 [2] d7 eb }

  condition:
    any of them
}