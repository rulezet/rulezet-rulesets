rule TTP_XOR_QUAD_CurrentVersionRun_e157 {
  strings:
    $key_e157 = { b2 38 [2] 96 36 [2] bd 1a [2] 93 38 [2] 87 23 [2] 88 39 [2] 96 24 [2] 94 25 [2] 8f 23 [2] 93 24 [2] 8f 0b }

  condition:
    any of them
}