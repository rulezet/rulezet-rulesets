rule TTP_XOR_QUAD_CurrentVersionRun_b236 {
  strings:
    $key_b236 = { e1 59 [2] c5 57 [2] ee 7b [2] c0 59 [2] d4 42 [2] db 58 [2] c5 45 [2] c7 44 [2] dc 42 [2] c0 45 [2] dc 6a }

  condition:
    any of them
}