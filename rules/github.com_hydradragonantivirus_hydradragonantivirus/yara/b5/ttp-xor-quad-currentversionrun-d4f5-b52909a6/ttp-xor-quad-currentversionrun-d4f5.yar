rule TTP_XOR_QUAD_CurrentVersionRun_d4f5 {
  strings:
    $key_d4f5 = { 87 9a [2] a3 94 [2] 88 b8 [2] a6 9a [2] b2 81 [2] bd 9b [2] a3 86 [2] a1 87 [2] ba 81 [2] a6 86 [2] ba a9 }

  condition:
    any of them
}