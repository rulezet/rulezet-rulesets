rule TTP_XOR_QUAD_CurrentVersionRun_e124 {
  strings:
    $key_e124 = { b2 4b [2] 96 45 [2] bd 69 [2] 93 4b [2] 87 50 [2] 88 4a [2] 96 57 [2] 94 56 [2] 8f 50 [2] 93 57 [2] 8f 78 }

  condition:
    any of them
}