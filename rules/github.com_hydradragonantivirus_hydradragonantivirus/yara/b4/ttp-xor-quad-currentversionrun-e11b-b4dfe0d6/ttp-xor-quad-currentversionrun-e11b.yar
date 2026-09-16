rule TTP_XOR_QUAD_CurrentVersionRun_e11b {
  strings:
    $key_e11b = { b2 74 [2] 96 7a [2] bd 56 [2] 93 74 [2] 87 6f [2] 88 75 [2] 96 68 [2] 94 69 [2] 8f 6f [2] 93 68 [2] 8f 47 }

  condition:
    any of them
}