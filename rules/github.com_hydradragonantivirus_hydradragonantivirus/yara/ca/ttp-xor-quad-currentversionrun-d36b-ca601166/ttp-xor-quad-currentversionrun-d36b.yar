rule TTP_XOR_QUAD_CurrentVersionRun_d36b {
  strings:
    $key_d36b = { 80 04 [2] a4 0a [2] 8f 26 [2] a1 04 [2] b5 1f [2] ba 05 [2] a4 18 [2] a6 19 [2] bd 1f [2] a1 18 [2] bd 37 }

  condition:
    any of them
}