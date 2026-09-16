rule TTP_XOR_QUAD_CurrentVersionRun_b26d {
  strings:
    $key_b26d = { e1 02 [2] c5 0c [2] ee 20 [2] c0 02 [2] d4 19 [2] db 03 [2] c5 1e [2] c7 1f [2] dc 19 [2] c0 1e [2] dc 31 }

  condition:
    any of them
}