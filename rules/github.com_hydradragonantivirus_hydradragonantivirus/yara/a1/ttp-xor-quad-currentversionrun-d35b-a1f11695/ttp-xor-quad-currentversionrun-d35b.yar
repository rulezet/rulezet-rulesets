rule TTP_XOR_QUAD_CurrentVersionRun_d35b {
  strings:
    $key_d35b = { 80 34 [2] a4 3a [2] 8f 16 [2] a1 34 [2] b5 2f [2] ba 35 [2] a4 28 [2] a6 29 [2] bd 2f [2] a1 28 [2] bd 07 }

  condition:
    any of them
}