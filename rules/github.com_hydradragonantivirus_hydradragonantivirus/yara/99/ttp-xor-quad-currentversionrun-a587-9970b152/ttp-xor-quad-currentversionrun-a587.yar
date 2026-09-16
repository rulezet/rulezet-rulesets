rule TTP_XOR_QUAD_CurrentVersionRun_a587 {
  strings:
    $key_a587 = { f6 e8 [2] d2 e6 [2] f9 ca [2] d7 e8 [2] c3 f3 [2] cc e9 [2] d2 f4 [2] d0 f5 [2] cb f3 [2] d7 f4 [2] cb db }

  condition:
    any of them
}