rule TTP_XOR_QUAD_CurrentVersionRun_b267 {
  strings:
    $key_b267 = { e1 08 [2] c5 06 [2] ee 2a [2] c0 08 [2] d4 13 [2] db 09 [2] c5 14 [2] c7 15 [2] dc 13 [2] c0 14 [2] dc 3b }

  condition:
    any of them
}