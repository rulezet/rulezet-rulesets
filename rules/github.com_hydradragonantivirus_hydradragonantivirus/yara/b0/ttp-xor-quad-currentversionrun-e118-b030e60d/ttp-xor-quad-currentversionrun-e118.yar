rule TTP_XOR_QUAD_CurrentVersionRun_e118 {
  strings:
    $key_e118 = { b2 77 [2] 96 79 [2] bd 55 [2] 93 77 [2] 87 6c [2] 88 76 [2] 96 6b [2] 94 6a [2] 8f 6c [2] 93 6b [2] 8f 44 }

  condition:
    any of them
}