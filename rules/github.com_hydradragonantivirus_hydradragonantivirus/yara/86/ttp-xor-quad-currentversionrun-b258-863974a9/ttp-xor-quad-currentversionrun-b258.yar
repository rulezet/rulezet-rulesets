rule TTP_XOR_QUAD_CurrentVersionRun_b258 {
  strings:
    $key_b258 = { e1 37 [2] c5 39 [2] ee 15 [2] c0 37 [2] d4 2c [2] db 36 [2] c5 2b [2] c7 2a [2] dc 2c [2] c0 2b [2] dc 04 }

  condition:
    any of them
}