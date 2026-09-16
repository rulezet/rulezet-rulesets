rule TTP_XOR_QUAD_CurrentVersionRun_beca {
  strings:
    $key_beca = { ed a5 [2] c9 ab [2] e2 87 [2] cc a5 [2] d8 be [2] d7 a4 [2] c9 b9 [2] cb b8 [2] d0 be [2] cc b9 [2] d0 96 }

  condition:
    any of them
}