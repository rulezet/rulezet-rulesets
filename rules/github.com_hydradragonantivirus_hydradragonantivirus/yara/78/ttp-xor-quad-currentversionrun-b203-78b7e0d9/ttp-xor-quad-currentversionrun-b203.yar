rule TTP_XOR_QUAD_CurrentVersionRun_b203 {
  strings:
    $key_b203 = { e1 6c [2] c5 62 [2] ee 4e [2] c0 6c [2] d4 77 [2] db 6d [2] c5 70 [2] c7 71 [2] dc 77 [2] c0 70 [2] dc 5f }

  condition:
    any of them
}