rule TTP_XOR_QUAD_CurrentVersionRun_a5be {
  strings:
    $key_a5be = { f6 d1 [2] d2 df [2] f9 f3 [2] d7 d1 [2] c3 ca [2] cc d0 [2] d2 cd [2] d0 cc [2] cb ca [2] d7 cd [2] cb e2 }

  condition:
    any of them
}