rule TTP_XOR_QUAD_CurrentVersionRun_b261 {
  strings:
    $key_b261 = { e1 0e [2] c5 00 [2] ee 2c [2] c0 0e [2] d4 15 [2] db 0f [2] c5 12 [2] c7 13 [2] dc 15 [2] c0 12 [2] dc 3d }

  condition:
    any of them
}