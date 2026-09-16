rule TTP_XOR_QUAD_CurrentVersionRun_b22a {
  strings:
    $key_b22a = { e1 45 [2] c5 4b [2] ee 67 [2] c0 45 [2] d4 5e [2] db 44 [2] c5 59 [2] c7 58 [2] dc 5e [2] c0 59 [2] dc 76 }

  condition:
    any of them
}