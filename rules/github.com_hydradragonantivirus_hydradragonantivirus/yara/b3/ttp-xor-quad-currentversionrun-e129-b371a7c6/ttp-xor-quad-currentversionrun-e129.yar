rule TTP_XOR_QUAD_CurrentVersionRun_e129 {
  strings:
    $key_e129 = { b2 46 [2] 96 48 [2] bd 64 [2] 93 46 [2] 87 5d [2] 88 47 [2] 96 5a [2] 94 5b [2] 8f 5d [2] 93 5a [2] 8f 75 }

  condition:
    any of them
}