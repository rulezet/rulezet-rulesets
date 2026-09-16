rule TTP_XOR_QUAD_CurrentVersionRun_b26c {
  strings:
    $key_b26c = { e1 03 [2] c5 0d [2] ee 21 [2] c0 03 [2] d4 18 [2] db 02 [2] c5 1f [2] c7 1e [2] dc 18 [2] c0 1f [2] dc 30 }

  condition:
    any of them
}