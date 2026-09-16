rule TTP_XOR_QUAD_CurrentVersionRun_b25b {
  strings:
    $key_b25b = { e1 34 [2] c5 3a [2] ee 16 [2] c0 34 [2] d4 2f [2] db 35 [2] c5 28 [2] c7 29 [2] dc 2f [2] c0 28 [2] dc 07 }

  condition:
    any of them
}