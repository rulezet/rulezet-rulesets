rule TTP_XOR_QUAD_CurrentVersionRun_d45b {
  strings:
    $key_d45b = { 87 34 [2] a3 3a [2] 88 16 [2] a6 34 [2] b2 2f [2] bd 35 [2] a3 28 [2] a1 29 [2] ba 2f [2] a6 28 [2] ba 07 }

  condition:
    any of them
}