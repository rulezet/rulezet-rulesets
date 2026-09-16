rule TTP_XOR_QUAD_CurrentVersionRun_e119 {
  strings:
    $key_e119 = { b2 76 [2] 96 78 [2] bd 54 [2] 93 76 [2] 87 6d [2] 88 77 [2] 96 6a [2] 94 6b [2] 8f 6d [2] 93 6a [2] 8f 45 }

  condition:
    any of them
}