rule TTP_XOR_QUAD_CurrentVersionRun_e149 {
  strings:
    $key_e149 = { b2 26 [2] 96 28 [2] bd 04 [2] 93 26 [2] 87 3d [2] 88 27 [2] 96 3a [2] 94 3b [2] 8f 3d [2] 93 3a [2] 8f 15 }

  condition:
    any of them
}