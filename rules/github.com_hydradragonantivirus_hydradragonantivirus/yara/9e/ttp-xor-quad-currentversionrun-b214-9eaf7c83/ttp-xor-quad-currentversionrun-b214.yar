rule TTP_XOR_QUAD_CurrentVersionRun_b214 {
  strings:
    $key_b214 = { e1 7b [2] c5 75 [2] ee 59 [2] c0 7b [2] d4 60 [2] db 7a [2] c5 67 [2] c7 66 [2] dc 60 [2] c0 67 [2] dc 48 }

  condition:
    any of them
}