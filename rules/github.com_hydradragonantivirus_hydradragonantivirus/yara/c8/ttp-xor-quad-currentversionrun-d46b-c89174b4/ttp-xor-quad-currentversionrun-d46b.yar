rule TTP_XOR_QUAD_CurrentVersionRun_d46b {
  strings:
    $key_d46b = { 87 04 [2] a3 0a [2] 88 26 [2] a6 04 [2] b2 1f [2] bd 05 [2] a3 18 [2] a1 19 [2] ba 1f [2] a6 18 [2] ba 37 }

  condition:
    any of them
}