rule TTP_XOR_QUAD_CurrentVersionRun_b26a {
  strings:
    $key_b26a = { e1 05 [2] c5 0b [2] ee 27 [2] c0 05 [2] d4 1e [2] db 04 [2] c5 19 [2] c7 18 [2] dc 1e [2] c0 19 [2] dc 36 }

  condition:
    any of them
}