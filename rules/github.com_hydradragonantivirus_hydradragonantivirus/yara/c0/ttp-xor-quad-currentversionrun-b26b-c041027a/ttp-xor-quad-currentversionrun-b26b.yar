rule TTP_XOR_QUAD_CurrentVersionRun_b26b {
  strings:
    $key_b26b = { e1 04 [2] c5 0a [2] ee 26 [2] c0 04 [2] d4 1f [2] db 05 [2] c5 18 [2] c7 19 [2] dc 1f [2] c0 18 [2] dc 37 }

  condition:
    any of them
}