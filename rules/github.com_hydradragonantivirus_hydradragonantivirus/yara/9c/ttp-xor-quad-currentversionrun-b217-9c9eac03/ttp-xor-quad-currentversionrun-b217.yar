rule TTP_XOR_QUAD_CurrentVersionRun_b217 {
  strings:
    $key_b217 = { e1 78 [2] c5 76 [2] ee 5a [2] c0 78 [2] d4 63 [2] db 79 [2] c5 64 [2] c7 65 [2] dc 63 [2] c0 64 [2] dc 4b }

  condition:
    any of them
}