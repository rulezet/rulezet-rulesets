rule TTP_XOR_QUAD_CurrentVersionRun_d30b {
  strings:
    $key_d30b = { 80 64 [2] a4 6a [2] 8f 46 [2] a1 64 [2] b5 7f [2] ba 65 [2] a4 78 [2] a6 79 [2] bd 7f [2] a1 78 [2] bd 57 }

  condition:
    any of them
}