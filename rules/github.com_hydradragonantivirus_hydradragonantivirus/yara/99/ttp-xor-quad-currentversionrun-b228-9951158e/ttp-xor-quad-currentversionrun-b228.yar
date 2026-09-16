rule TTP_XOR_QUAD_CurrentVersionRun_b228 {
  strings:
    $key_b228 = { e1 47 [2] c5 49 [2] ee 65 [2] c0 47 [2] d4 5c [2] db 46 [2] c5 5b [2] c7 5a [2] dc 5c [2] c0 5b [2] dc 74 }

  condition:
    any of them
}