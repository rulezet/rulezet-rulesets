rule TTP_XOR_QUAD_CurrentVersionRun_b224 {
  strings:
    $key_b224 = { e1 4b [2] c5 45 [2] ee 69 [2] c0 4b [2] d4 50 [2] db 4a [2] c5 57 [2] c7 56 [2] dc 50 [2] c0 57 [2] dc 78 }

  condition:
    any of them
}