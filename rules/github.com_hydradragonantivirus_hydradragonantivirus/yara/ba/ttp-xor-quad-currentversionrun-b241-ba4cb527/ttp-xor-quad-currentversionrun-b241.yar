rule TTP_XOR_QUAD_CurrentVersionRun_b241 {
  strings:
    $key_b241 = { e1 2e [2] c5 20 [2] ee 0c [2] c0 2e [2] d4 35 [2] db 2f [2] c5 32 [2] c7 33 [2] dc 35 [2] c0 32 [2] dc 1d }

  condition:
    any of them
}