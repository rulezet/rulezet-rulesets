rule TTP_XOR_QUAD_CurrentVersionRun_b271 {
  strings:
    $key_b271 = { e1 1e [2] c5 10 [2] ee 3c [2] c0 1e [2] d4 05 [2] db 1f [2] c5 02 [2] c7 03 [2] dc 05 [2] c0 02 [2] dc 2d }

  condition:
    any of them
}