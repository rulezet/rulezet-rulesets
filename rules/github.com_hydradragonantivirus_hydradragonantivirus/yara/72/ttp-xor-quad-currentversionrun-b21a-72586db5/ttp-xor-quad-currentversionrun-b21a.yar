rule TTP_XOR_QUAD_CurrentVersionRun_b21a {
  strings:
    $key_b21a = { e1 75 [2] c5 7b [2] ee 57 [2] c0 75 [2] d4 6e [2] db 74 [2] c5 69 [2] c7 68 [2] dc 6e [2] c0 69 [2] dc 46 }

  condition:
    any of them
}