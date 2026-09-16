rule TTP_XOR_QUAD_CurrentVersionRun_b9a5 {
  strings:
    $key_b9a5 = { ea ca [2] ce c4 [2] e5 e8 [2] cb ca [2] df d1 [2] d0 cb [2] ce d6 [2] cc d7 [2] d7 d1 [2] cb d6 [2] d7 f9 }

  condition:
    any of them
}