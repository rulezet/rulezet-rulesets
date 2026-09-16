rule TTP_XOR_QUAD_CurrentVersionRun_e175 {
  strings:
    $key_e175 = { b2 1a [2] 96 14 [2] bd 38 [2] 93 1a [2] 87 01 [2] 88 1b [2] 96 06 [2] 94 07 [2] 8f 01 [2] 93 06 [2] 8f 29 }

  condition:
    any of them
}