rule TTP_XOR_QUAD_CurrentVersionRun_e15b {
  strings:
    $key_e15b = { b2 34 [2] 96 3a [2] bd 16 [2] 93 34 [2] 87 2f [2] 88 35 [2] 96 28 [2] 94 29 [2] 8f 2f [2] 93 28 [2] 8f 07 }

  condition:
    any of them
}