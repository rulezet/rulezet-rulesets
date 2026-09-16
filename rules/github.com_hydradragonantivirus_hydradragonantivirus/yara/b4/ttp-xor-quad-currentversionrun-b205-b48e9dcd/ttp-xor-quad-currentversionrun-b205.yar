rule TTP_XOR_QUAD_CurrentVersionRun_b205 {
  strings:
    $key_b205 = { e1 6a [2] c5 64 [2] ee 48 [2] c0 6a [2] d4 71 [2] db 6b [2] c5 76 [2] c7 77 [2] dc 71 [2] c0 76 [2] dc 59 }

  condition:
    any of them
}