rule TTP_XOR_QUAD_CurrentVersionRun_d40b {
  strings:
    $key_d40b = { 87 64 [2] a3 6a [2] 88 46 [2] a6 64 [2] b2 7f [2] bd 65 [2] a3 78 [2] a1 79 [2] ba 7f [2] a6 78 [2] ba 57 }

  condition:
    any of them
}