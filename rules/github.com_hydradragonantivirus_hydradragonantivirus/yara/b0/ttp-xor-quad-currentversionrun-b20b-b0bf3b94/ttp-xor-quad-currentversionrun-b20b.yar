rule TTP_XOR_QUAD_CurrentVersionRun_b20b {
  strings:
    $key_b20b = { e1 64 [2] c5 6a [2] ee 46 [2] c0 64 [2] d4 7f [2] db 65 [2] c5 78 [2] c7 79 [2] dc 7f [2] c0 78 [2] dc 57 }

  condition:
    any of them
}