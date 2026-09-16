rule TTP_XOR_QUAD_CurrentVersionRun_b243 {
  strings:
    $key_b243 = { e1 2c [2] c5 22 [2] ee 0e [2] c0 2c [2] d4 37 [2] db 2d [2] c5 30 [2] c7 31 [2] dc 37 [2] c0 30 [2] dc 1f }

  condition:
    any of them
}