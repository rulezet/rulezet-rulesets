rule TTP_XOR_QUAD_CurrentVersionRun_d34b {
  strings:
    $key_d34b = { 80 24 [2] a4 2a [2] 8f 06 [2] a1 24 [2] b5 3f [2] ba 25 [2] a4 38 [2] a6 39 [2] bd 3f [2] a1 38 [2] bd 17 }

  condition:
    any of them
}