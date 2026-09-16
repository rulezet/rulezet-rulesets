rule TTP_XOR_QUAD_CurrentVersionRun_d465 {
  strings:
    $key_d465 = { 87 0a [2] a3 04 [2] 88 28 [2] a6 0a [2] b2 11 [2] bd 0b [2] a3 16 [2] a1 17 [2] ba 11 [2] a6 16 [2] ba 39 }

  condition:
    any of them
}