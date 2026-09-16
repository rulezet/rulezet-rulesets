rule TTP_XOR_QUAD_CurrentVersionRun_d371 {
  strings:
    $key_d371 = { 80 1e [2] a4 10 [2] 8f 3c [2] a1 1e [2] b5 05 [2] ba 1f [2] a4 02 [2] a6 03 [2] bd 05 [2] a1 02 [2] bd 2d }

  condition:
    any of them
}