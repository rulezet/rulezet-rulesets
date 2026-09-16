rule TTP_XOR_QUAD_CurrentVersionRun_d305 {
  strings:
    $key_d305 = { 80 6a [2] a4 64 [2] 8f 48 [2] a1 6a [2] b5 71 [2] ba 6b [2] a4 76 [2] a6 77 [2] bd 71 [2] a1 76 [2] bd 59 }

  condition:
    any of them
}