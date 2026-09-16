rule TTP_XOR_QUAD_CurrentVersionRun_d42b {
  strings:
    $key_d42b = { 87 44 [2] a3 4a [2] 88 66 [2] a6 44 [2] b2 5f [2] bd 45 [2] a3 58 [2] a1 59 [2] ba 5f [2] a6 58 [2] ba 77 }

  condition:
    any of them
}