rule TTP_XOR_QUAD_CurrentVersionRun_d478 {
  strings:
    $key_d478 = { 87 17 [2] a3 19 [2] 88 35 [2] a6 17 [2] b2 0c [2] bd 16 [2] a3 0b [2] a1 0a [2] ba 0c [2] a6 0b [2] ba 24 }

  condition:
    any of them
}