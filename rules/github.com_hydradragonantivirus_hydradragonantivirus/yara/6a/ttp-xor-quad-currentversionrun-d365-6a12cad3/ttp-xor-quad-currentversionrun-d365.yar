rule TTP_XOR_QUAD_CurrentVersionRun_d365 {
  strings:
    $key_d365 = { 80 0a [2] a4 04 [2] 8f 28 [2] a1 0a [2] b5 11 [2] ba 0b [2] a4 16 [2] a6 17 [2] bd 11 [2] a1 16 [2] bd 39 }

  condition:
    any of them
}