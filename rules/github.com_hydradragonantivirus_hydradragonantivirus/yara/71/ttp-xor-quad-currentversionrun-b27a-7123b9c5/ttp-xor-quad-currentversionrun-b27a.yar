rule TTP_XOR_QUAD_CurrentVersionRun_b27a {
  strings:
    $key_b27a = { e1 15 [2] c5 1b [2] ee 37 [2] c0 15 [2] d4 0e [2] db 14 [2] c5 09 [2] c7 08 [2] dc 0e [2] c0 09 [2] dc 26 }

  condition:
    any of them
}