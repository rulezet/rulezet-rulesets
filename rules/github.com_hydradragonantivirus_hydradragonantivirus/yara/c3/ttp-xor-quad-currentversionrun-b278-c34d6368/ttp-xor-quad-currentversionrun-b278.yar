rule TTP_XOR_QUAD_CurrentVersionRun_b278 {
  strings:
    $key_b278 = { e1 17 [2] c5 19 [2] ee 35 [2] c0 17 [2] d4 0c [2] db 16 [2] c5 0b [2] c7 0a [2] dc 0c [2] c0 0b [2] dc 24 }

  condition:
    any of them
}