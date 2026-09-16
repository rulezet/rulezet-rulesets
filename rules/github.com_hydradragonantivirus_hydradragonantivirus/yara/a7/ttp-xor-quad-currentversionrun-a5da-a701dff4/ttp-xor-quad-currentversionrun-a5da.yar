rule TTP_XOR_QUAD_CurrentVersionRun_a5da {
  strings:
    $key_a5da = { f6 b5 [2] d2 bb [2] f9 97 [2] d7 b5 [2] c3 ae [2] cc b4 [2] d2 a9 [2] d0 a8 [2] cb ae [2] d7 a9 [2] cb 86 }

  condition:
    any of them
}