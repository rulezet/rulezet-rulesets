rule TTP_XOR_QUAD_CurrentVersionRun_a5b9 {
  strings:
    $key_a5b9 = { f6 d6 [2] d2 d8 [2] f9 f4 [2] d7 d6 [2] c3 cd [2] cc d7 [2] d2 ca [2] d0 cb [2] cb cd [2] d7 ca [2] cb e5 }

  condition:
    any of them
}