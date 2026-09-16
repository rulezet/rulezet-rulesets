rule TTP_XOR_QUAD_CurrentVersionRun_d379 {
  strings:
    $key_d379 = { 80 16 [2] a4 18 [2] 8f 34 [2] a1 16 [2] b5 0d [2] ba 17 [2] a4 0a [2] a6 0b [2] bd 0d [2] a1 0a [2] bd 25 }

  condition:
    any of them
}