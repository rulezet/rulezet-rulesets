rule TTP_XOR_QUAD_CurrentVersionRun_d339 {
  strings:
    $key_d339 = { 80 56 [2] a4 58 [2] 8f 74 [2] a1 56 [2] b5 4d [2] ba 57 [2] a4 4a [2] a6 4b [2] bd 4d [2] a1 4a [2] bd 65 }

  condition:
    any of them
}