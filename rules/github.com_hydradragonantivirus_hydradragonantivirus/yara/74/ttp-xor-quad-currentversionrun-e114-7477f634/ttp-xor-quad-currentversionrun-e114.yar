rule TTP_XOR_QUAD_CurrentVersionRun_e114 {
  strings:
    $key_e114 = { b2 7b [2] 96 75 [2] bd 59 [2] 93 7b [2] 87 60 [2] 88 7a [2] 96 67 [2] 94 66 [2] 8f 60 [2] 93 67 [2] 8f 48 }

  condition:
    any of them
}