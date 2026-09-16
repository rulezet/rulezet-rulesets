rule TTP_XOR_QUAD_CurrentVersionRun_b216 {
  strings:
    $key_b216 = { e1 79 [2] c5 77 [2] ee 5b [2] c0 79 [2] d4 62 [2] db 78 [2] c5 65 [2] c7 64 [2] dc 62 [2] c0 65 [2] dc 4a }

  condition:
    any of them
}