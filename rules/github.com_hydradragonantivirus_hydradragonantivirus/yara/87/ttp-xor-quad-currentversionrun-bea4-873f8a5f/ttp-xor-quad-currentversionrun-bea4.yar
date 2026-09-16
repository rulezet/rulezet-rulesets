rule TTP_XOR_QUAD_CurrentVersionRun_bea4 {
  strings:
    $key_bea4 = { ed cb [2] c9 c5 [2] e2 e9 [2] cc cb [2] d8 d0 [2] d7 ca [2] c9 d7 [2] cb d6 [2] d0 d0 [2] cc d7 [2] d0 f8 }

  condition:
    any of them
}