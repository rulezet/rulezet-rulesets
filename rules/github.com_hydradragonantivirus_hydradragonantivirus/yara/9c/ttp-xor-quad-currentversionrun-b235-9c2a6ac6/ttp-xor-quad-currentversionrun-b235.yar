rule TTP_XOR_QUAD_CurrentVersionRun_b235 {
  strings:
    $key_b235 = { e1 5a [2] c5 54 [2] ee 78 [2] c0 5a [2] d4 41 [2] db 5b [2] c5 46 [2] c7 47 [2] dc 41 [2] c0 46 [2] dc 69 }

  condition:
    any of them
}