rule TTP_XOR_QUAD_CurrentVersionRun_b23a {
  strings:
    $key_b23a = { e1 55 [2] c5 5b [2] ee 77 [2] c0 55 [2] d4 4e [2] db 54 [2] c5 49 [2] c7 48 [2] dc 4e [2] c0 49 [2] dc 66 }

  condition:
    any of them
}