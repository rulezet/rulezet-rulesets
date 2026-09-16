rule TTP_XOR_QUAD_CurrentVersionRun_e108 {
  strings:
    $key_e108 = { b2 67 [2] 96 69 [2] bd 45 [2] 93 67 [2] 87 7c [2] 88 66 [2] 96 7b [2] 94 7a [2] 8f 7c [2] 93 7b [2] 8f 54 }

  condition:
    any of them
}