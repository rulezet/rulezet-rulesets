rule TTP_XOR_QUAD_CurrentVersionRun_b2c4 {
  strings:
    $key_b2c4 = { e1 ab [2] c5 a5 [2] ee 89 [2] c0 ab [2] d4 b0 [2] db aa [2] c5 b7 [2] c7 b6 [2] dc b0 [2] c0 b7 [2] dc 98 }

  condition:
    any of them
}