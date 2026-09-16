rule TTP_XOR_QUAD_CurrentVersionRun_bccc {
  strings:
    $key_bccc = { ef a3 [2] cb ad [2] e0 81 [2] ce a3 [2] da b8 [2] d5 a2 [2] cb bf [2] c9 be [2] d2 b8 [2] ce bf [2] d2 90 }

  condition:
    any of them
}