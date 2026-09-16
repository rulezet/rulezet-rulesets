rule TTP_XOR_QUAD_CurrentVersionRun_bcb8 {
  strings:
    $key_bcb8 = { ef d7 [2] cb d9 [2] e0 f5 [2] ce d7 [2] da cc [2] d5 d6 [2] cb cb [2] c9 ca [2] d2 cc [2] ce cb [2] d2 e4 }

  condition:
    any of them
}