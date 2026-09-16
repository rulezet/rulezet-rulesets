rule TTP_XOR_QUAD_CurrentVersionRun_b22d {
  strings:
    $key_b22d = { e1 42 [2] c5 4c [2] ee 60 [2] c0 42 [2] d4 59 [2] db 43 [2] c5 5e [2] c7 5f [2] dc 59 [2] c0 5e [2] dc 71 }

  condition:
    any of them
}