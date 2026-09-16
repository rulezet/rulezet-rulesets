rule TTP_XOR_QUAD_CurrentVersionRun_cf39 {
  strings:
    $key_cf39 = { 9c 56 [2] b8 58 [2] 93 74 [2] bd 56 [2] a9 4d [2] a6 57 [2] b8 4a [2] ba 4b [2] a1 4d [2] bd 4a [2] a1 65 }

  condition:
    any of them
}