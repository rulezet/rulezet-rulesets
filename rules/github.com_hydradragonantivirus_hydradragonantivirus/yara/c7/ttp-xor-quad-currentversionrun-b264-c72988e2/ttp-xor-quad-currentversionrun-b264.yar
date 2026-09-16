rule TTP_XOR_QUAD_CurrentVersionRun_b264 {
  strings:
    $key_b264 = { e1 0b [2] c5 05 [2] ee 29 [2] c0 0b [2] d4 10 [2] db 0a [2] c5 17 [2] c7 16 [2] dc 10 [2] c0 17 [2] dc 38 }

  condition:
    any of them
}