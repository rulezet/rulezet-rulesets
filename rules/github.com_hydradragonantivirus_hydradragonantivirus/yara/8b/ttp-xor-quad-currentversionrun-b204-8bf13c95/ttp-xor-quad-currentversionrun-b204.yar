rule TTP_XOR_QUAD_CurrentVersionRun_b204 {
  strings:
    $key_b204 = { e1 6b [2] c5 65 [2] ee 49 [2] c0 6b [2] d4 70 [2] db 6a [2] c5 77 [2] c7 76 [2] dc 70 [2] c0 77 [2] dc 58 }

  condition:
    any of them
}