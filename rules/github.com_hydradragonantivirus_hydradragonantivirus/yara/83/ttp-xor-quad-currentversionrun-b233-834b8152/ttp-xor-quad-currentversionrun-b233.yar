rule TTP_XOR_QUAD_CurrentVersionRun_b233 {
  strings:
    $key_b233 = { e1 5c [2] c5 52 [2] ee 7e [2] c0 5c [2] d4 47 [2] db 5d [2] c5 40 [2] c7 41 [2] dc 47 [2] c0 40 [2] dc 6f }

  condition:
    any of them
}