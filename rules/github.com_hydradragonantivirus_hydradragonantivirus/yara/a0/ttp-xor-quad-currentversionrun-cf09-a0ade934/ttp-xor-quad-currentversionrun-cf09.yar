rule TTP_XOR_QUAD_CurrentVersionRun_cf09 {
  strings:
    $key_cf09 = { 9c 66 [2] b8 68 [2] 93 44 [2] bd 66 [2] a9 7d [2] a6 67 [2] b8 7a [2] ba 7b [2] a1 7d [2] bd 7a [2] a1 55 }

  condition:
    any of them
}