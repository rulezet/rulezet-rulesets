rule TTP_XOR_QUAD_CurrentVersionRun_adcc {
  strings:
    $key_adcc = { fe a3 [2] da ad [2] f1 81 [2] df a3 [2] cb b8 [2] c4 a2 [2] da bf [2] d8 be [2] c3 b8 [2] df bf [2] c3 90 }

  condition:
    any of them
}