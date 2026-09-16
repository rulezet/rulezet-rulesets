rule TTP_XOR_QUAD_CurrentVersionRun_b201 {
  strings:
    $key_b201 = { e1 6e [2] c5 60 [2] ee 4c [2] c0 6e [2] d4 75 [2] db 6f [2] c5 72 [2] c7 73 [2] dc 75 [2] c0 72 [2] dc 5d }

  condition:
    any of them
}