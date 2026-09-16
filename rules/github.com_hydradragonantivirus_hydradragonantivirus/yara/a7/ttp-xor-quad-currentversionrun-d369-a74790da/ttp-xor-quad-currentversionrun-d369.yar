rule TTP_XOR_QUAD_CurrentVersionRun_d369 {
  strings:
    $key_d369 = { 80 06 [2] a4 08 [2] 8f 24 [2] a1 06 [2] b5 1d [2] ba 07 [2] a4 1a [2] a6 1b [2] bd 1d [2] a1 1a [2] bd 35 }

  condition:
    any of them
}