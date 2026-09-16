rule TTP_XOR_QUAD_CurrentVersionRun_b25d {
  strings:
    $key_b25d = { e1 32 [2] c5 3c [2] ee 10 [2] c0 32 [2] d4 29 [2] db 33 [2] c5 2e [2] c7 2f [2] dc 29 [2] c0 2e [2] dc 01 }

  condition:
    any of them
}