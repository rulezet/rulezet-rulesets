rule TTP_XOR_QUAD_CurrentVersionRun_b27b {
  strings:
    $key_b27b = { e1 14 [2] c5 1a [2] ee 36 [2] c0 14 [2] d4 0f [2] db 15 [2] c5 08 [2] c7 09 [2] dc 0f [2] c0 08 [2] dc 27 }

  condition:
    any of them
}