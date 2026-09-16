rule TTP_XOR_QUAD_CurrentVersionRun_cf70 {
  strings:
    $key_cf70 = { 9c 1f [2] b8 11 [2] 93 3d [2] bd 1f [2] a9 04 [2] a6 1e [2] b8 03 [2] ba 02 [2] a1 04 [2] bd 03 [2] a1 2c }

  condition:
    any of them
}