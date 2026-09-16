rule TTP_XOR_QUAD_CurrentVersionRun_b2d9 {
  strings:
    $key_b2d9 = { e1 b6 [2] c5 b8 [2] ee 94 [2] c0 b6 [2] d4 ad [2] db b7 [2] c5 aa [2] c7 ab [2] dc ad [2] c0 aa [2] dc 85 }

  condition:
    any of them
}