rule TTP_XOR_QUAD_CurrentVersionRun_d341 {
  strings:
    $key_d341 = { 80 2e [2] a4 20 [2] 8f 0c [2] a1 2e [2] b5 35 [2] ba 2f [2] a4 32 [2] a6 33 [2] bd 35 [2] a1 32 [2] bd 1d }

  condition:
    any of them
}