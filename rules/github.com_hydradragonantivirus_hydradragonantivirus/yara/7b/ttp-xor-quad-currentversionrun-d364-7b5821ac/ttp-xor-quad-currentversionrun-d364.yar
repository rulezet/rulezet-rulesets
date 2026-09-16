rule TTP_XOR_QUAD_CurrentVersionRun_d364 {
  strings:
    $key_d364 = { 80 0b [2] a4 05 [2] 8f 29 [2] a1 0b [2] b5 10 [2] ba 0a [2] a4 17 [2] a6 16 [2] bd 10 [2] a1 17 [2] bd 38 }

  condition:
    any of them
}