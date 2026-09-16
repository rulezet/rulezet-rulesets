rule TTP_XOR_QUAD_CurrentVersionRun_a997 {
  strings:
    $key_a997 = { fa f8 [2] de f6 [2] f5 da [2] db f8 [2] cf e3 [2] c0 f9 [2] de e4 [2] dc e5 [2] c7 e3 [2] db e4 [2] c7 cb }

  condition:
    any of them
}