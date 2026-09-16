rule TTP_XOR_QUAD_CurrentVersionRun_e1e4 {
  strings:
    $key_e1e4 = { b2 8b [2] 96 85 [2] bd a9 [2] 93 8b [2] 87 90 [2] 88 8a [2] 96 97 [2] 94 96 [2] 8f 90 [2] 93 97 [2] 8f b8 }

  condition:
    any of them
}