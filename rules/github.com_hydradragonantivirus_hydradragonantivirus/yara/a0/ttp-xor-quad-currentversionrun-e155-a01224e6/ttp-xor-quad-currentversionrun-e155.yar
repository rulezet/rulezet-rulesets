rule TTP_XOR_QUAD_CurrentVersionRun_e155 {
  strings:
    $key_e155 = { b2 3a [2] 96 34 [2] bd 18 [2] 93 3a [2] 87 21 [2] 88 3b [2] 96 26 [2] 94 27 [2] 8f 21 [2] 93 26 [2] 8f 09 }

  condition:
    any of them
}