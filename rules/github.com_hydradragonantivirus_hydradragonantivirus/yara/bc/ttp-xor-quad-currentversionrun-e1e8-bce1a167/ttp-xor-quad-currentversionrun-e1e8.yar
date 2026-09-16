rule TTP_XOR_QUAD_CurrentVersionRun_e1e8 {
  strings:
    $key_e1e8 = { b2 87 [2] 96 89 [2] bd a5 [2] 93 87 [2] 87 9c [2] 88 86 [2] 96 9b [2] 94 9a [2] 8f 9c [2] 93 9b [2] 8f b4 }

  condition:
    any of them
}