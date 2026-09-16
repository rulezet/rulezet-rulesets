rule TTP_XOR_QUAD_CurrentVersionRun_d4f4 {
  strings:
    $key_d4f4 = { 87 9b [2] a3 95 [2] 88 b9 [2] a6 9b [2] b2 80 [2] bd 9a [2] a3 87 [2] a1 86 [2] ba 80 [2] a6 87 [2] ba a8 }

  condition:
    any of them
}