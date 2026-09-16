rule TTP_XOR_QUAD_CurrentVersionRun_b251 {
  strings:
    $key_b251 = { e1 3e [2] c5 30 [2] ee 1c [2] c0 3e [2] d4 25 [2] db 3f [2] c5 22 [2] c7 23 [2] dc 25 [2] c0 22 [2] dc 0d }

  condition:
    any of them
}