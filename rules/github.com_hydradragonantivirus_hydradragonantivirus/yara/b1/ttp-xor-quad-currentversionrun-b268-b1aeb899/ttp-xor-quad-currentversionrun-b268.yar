rule TTP_XOR_QUAD_CurrentVersionRun_b268 {
  strings:
    $key_b268 = { e1 07 [2] c5 09 [2] ee 25 [2] c0 07 [2] d4 1c [2] db 06 [2] c5 1b [2] c7 1a [2] dc 1c [2] c0 1b [2] dc 34 }

  condition:
    any of them
}