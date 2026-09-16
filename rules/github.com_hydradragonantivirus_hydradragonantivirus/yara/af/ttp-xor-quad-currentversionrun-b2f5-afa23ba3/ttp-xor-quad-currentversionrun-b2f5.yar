rule TTP_XOR_QUAD_CurrentVersionRun_b2f5 {
  strings:
    $key_b2f5 = { e1 9a [2] c5 94 [2] ee b8 [2] c0 9a [2] d4 81 [2] db 9b [2] c5 86 [2] c7 87 [2] dc 81 [2] c0 86 [2] dc a9 }

  condition:
    any of them
}