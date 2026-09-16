rule TTP_XOR_QUAD_CurrentVersionRun_e135 {
  strings:
    $key_e135 = { b2 5a [2] 96 54 [2] bd 78 [2] 93 5a [2] 87 41 [2] 88 5b [2] 96 46 [2] 94 47 [2] 8f 41 [2] 93 46 [2] 8f 69 }

  condition:
    any of them
}