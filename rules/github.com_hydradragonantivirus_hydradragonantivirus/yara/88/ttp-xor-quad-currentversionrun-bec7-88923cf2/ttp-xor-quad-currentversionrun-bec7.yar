rule TTP_XOR_QUAD_CurrentVersionRun_bec7 {
  strings:
    $key_bec7 = { ed a8 [2] c9 a6 [2] e2 8a [2] cc a8 [2] d8 b3 [2] d7 a9 [2] c9 b4 [2] cb b5 [2] d0 b3 [2] cc b4 [2] d0 9b }

  condition:
    any of them
}