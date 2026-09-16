rule TTP_XOR_QUAD_CurrentVersionRun_b244 {
  strings:
    $key_b244 = { e1 2b [2] c5 25 [2] ee 09 [2] c0 2b [2] d4 30 [2] db 2a [2] c5 37 [2] c7 36 [2] dc 30 [2] c0 37 [2] dc 18 }

  condition:
    any of them
}