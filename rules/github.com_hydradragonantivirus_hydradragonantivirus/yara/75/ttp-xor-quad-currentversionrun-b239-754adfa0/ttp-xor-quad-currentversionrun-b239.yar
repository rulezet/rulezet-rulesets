rule TTP_XOR_QUAD_CurrentVersionRun_b239 {
  strings:
    $key_b239 = { e1 56 [2] c5 58 [2] ee 74 [2] c0 56 [2] d4 4d [2] db 57 [2] c5 4a [2] c7 4b [2] dc 4d [2] c0 4a [2] dc 65 }

  condition:
    any of them
}