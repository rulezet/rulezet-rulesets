rule TTP_XOR_QUAD_CurrentVersionRun_d37b {
  strings:
    $key_d37b = { 80 14 [2] a4 1a [2] 8f 36 [2] a1 14 [2] b5 0f [2] ba 15 [2] a4 08 [2] a6 09 [2] bd 0f [2] a1 08 [2] bd 27 }

  condition:
    any of them
}