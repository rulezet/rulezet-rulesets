rule TTP_XOR_QUAD_CurrentVersionRun_b207 {
  strings:
    $key_b207 = { e1 68 [2] c5 66 [2] ee 4a [2] c0 68 [2] d4 73 [2] db 69 [2] c5 74 [2] c7 75 [2] dc 73 [2] c0 74 [2] dc 5b }

  condition:
    any of them
}