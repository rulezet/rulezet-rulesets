rule TTP_XOR_QUAD_CurrentVersionRun_c871 {
  strings:
    $key_c871 = { 9b 1e [2] bf 10 [2] 94 3c [2] ba 1e [2] ae 05 [2] a1 1f [2] bf 02 [2] bd 03 [2] a6 05 [2] ba 02 [2] a6 2d }

  condition:
    any of them
}