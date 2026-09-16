rule TTP_XOR_QUAD_CurrentVersionRun_b242 {
  strings:
    $key_b242 = { e1 2d [2] c5 23 [2] ee 0f [2] c0 2d [2] d4 36 [2] db 2c [2] c5 31 [2] c7 30 [2] dc 36 [2] c0 31 [2] dc 1e }

  condition:
    any of them
}