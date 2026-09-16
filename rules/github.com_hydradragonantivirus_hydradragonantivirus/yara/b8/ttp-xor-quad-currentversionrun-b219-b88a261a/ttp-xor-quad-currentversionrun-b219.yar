rule TTP_XOR_QUAD_CurrentVersionRun_b219 {
  strings:
    $key_b219 = { e1 76 [2] c5 78 [2] ee 54 [2] c0 76 [2] d4 6d [2] db 77 [2] c5 6a [2] c7 6b [2] dc 6d [2] c0 6a [2] dc 45 }

  condition:
    any of them
}