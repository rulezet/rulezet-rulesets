rule TTP_XOR_QUAD_CurrentVersionRun_d370 {
  strings:
    $key_d370 = { 80 1f [2] a4 11 [2] 8f 3d [2] a1 1f [2] b5 04 [2] ba 1e [2] a4 03 [2] a6 02 [2] bd 04 [2] a1 03 [2] bd 2c }

  condition:
    any of them
}