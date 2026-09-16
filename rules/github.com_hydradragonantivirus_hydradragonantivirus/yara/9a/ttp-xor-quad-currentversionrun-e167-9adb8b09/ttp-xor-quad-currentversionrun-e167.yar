rule TTP_XOR_QUAD_CurrentVersionRun_e167 {
  strings:
    $key_e167 = { b2 08 [2] 96 06 [2] bd 2a [2] 93 08 [2] 87 13 [2] 88 09 [2] 96 14 [2] 94 15 [2] 8f 13 [2] 93 14 [2] 8f 3b }

  condition:
    any of them
}