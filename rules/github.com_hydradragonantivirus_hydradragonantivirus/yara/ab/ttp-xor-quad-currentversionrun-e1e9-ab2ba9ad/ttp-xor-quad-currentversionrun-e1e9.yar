rule TTP_XOR_QUAD_CurrentVersionRun_e1e9 {
  strings:
    $key_e1e9 = { b2 86 [2] 96 88 [2] bd a4 [2] 93 86 [2] 87 9d [2] 88 87 [2] 96 9a [2] 94 9b [2] 8f 9d [2] 93 9a [2] 8f b5 }

  condition:
    any of them
}