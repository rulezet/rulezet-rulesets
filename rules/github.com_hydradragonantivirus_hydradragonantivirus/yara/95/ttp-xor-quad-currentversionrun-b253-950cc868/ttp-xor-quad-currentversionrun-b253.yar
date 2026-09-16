rule TTP_XOR_QUAD_CurrentVersionRun_b253 {
  strings:
    $key_b253 = { e1 3c [2] c5 32 [2] ee 1e [2] c0 3c [2] d4 27 [2] db 3d [2] c5 20 [2] c7 21 [2] dc 27 [2] c0 20 [2] dc 0f }

  condition:
    any of them
}