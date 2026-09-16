rule TTP_XOR_QUAD_CurrentVersionRun_e393 {
  strings:
    $key_e393 = { b0 fc [2] 94 f2 [2] bf de [2] 91 fc [2] 85 e7 [2] 8a fd [2] 94 e0 [2] 96 e1 [2] 8d e7 [2] 91 e0 [2] 8d cf }

  condition:
    any of them
}