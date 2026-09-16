rule TTP_XOR_QUAD_CurrentVersionRun_adcd {
  strings:
    $key_adcd = { fe a2 [2] da ac [2] f1 80 [2] df a2 [2] cb b9 [2] c4 a3 [2] da be [2] d8 bf [2] c3 b9 [2] df be [2] c3 91 }

  condition:
    any of them
}