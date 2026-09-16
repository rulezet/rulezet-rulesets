rule TTP_XOR_QUAD_CurrentVersionRun_b229 {
  strings:
    $key_b229 = { e1 46 [2] c5 48 [2] ee 64 [2] c0 46 [2] d4 5d [2] db 47 [2] c5 5a [2] c7 5b [2] dc 5d [2] c0 5a [2] dc 75 }

  condition:
    any of them
}