rule TTP_XOR_QUAD_CurrentVersionRun_d417 {
  strings:
    $key_d417 = { 87 78 [2] a3 76 [2] 88 5a [2] a6 78 [2] b2 63 [2] bd 79 [2] a3 64 [2] a1 65 [2] ba 63 [2] a6 64 [2] ba 4b }

  condition:
    any of them
}