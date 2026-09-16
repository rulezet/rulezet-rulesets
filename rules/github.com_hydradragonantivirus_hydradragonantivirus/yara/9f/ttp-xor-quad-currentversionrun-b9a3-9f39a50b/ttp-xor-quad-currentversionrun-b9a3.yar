rule TTP_XOR_QUAD_CurrentVersionRun_b9a3 {
  strings:
    $key_b9a3 = { ea cc [2] ce c2 [2] e5 ee [2] cb cc [2] df d7 [2] d0 cd [2] ce d0 [2] cc d1 [2] d7 d7 [2] cb d0 [2] d7 ff }

  condition:
    any of them
}