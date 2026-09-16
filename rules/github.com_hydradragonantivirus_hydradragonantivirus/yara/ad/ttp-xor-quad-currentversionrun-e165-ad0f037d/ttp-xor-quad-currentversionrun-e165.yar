rule TTP_XOR_QUAD_CurrentVersionRun_e165 {
  strings:
    $key_e165 = { b2 0a [2] 96 04 [2] bd 28 [2] 93 0a [2] 87 11 [2] 88 0b [2] 96 16 [2] 94 17 [2] 8f 11 [2] 93 16 [2] 8f 39 }

  condition:
    any of them
}