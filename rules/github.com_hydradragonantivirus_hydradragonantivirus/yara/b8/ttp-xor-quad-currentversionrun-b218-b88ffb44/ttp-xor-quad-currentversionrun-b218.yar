rule TTP_XOR_QUAD_CurrentVersionRun_b218 {
  strings:
    $key_b218 = { e1 77 [2] c5 79 [2] ee 55 [2] c0 77 [2] d4 6c [2] db 76 [2] c5 6b [2] c7 6a [2] dc 6c [2] c0 6b [2] dc 44 }

  condition:
    any of them
}