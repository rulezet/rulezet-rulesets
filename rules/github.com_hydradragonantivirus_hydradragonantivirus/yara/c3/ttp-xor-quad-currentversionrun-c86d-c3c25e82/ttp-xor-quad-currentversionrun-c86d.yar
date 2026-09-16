rule TTP_XOR_QUAD_CurrentVersionRun_c86d {
  strings:
    $key_c86d = { 9b 02 [2] bf 0c [2] 94 20 [2] ba 02 [2] ae 19 [2] a1 03 [2] bf 1e [2] bd 1f [2] a6 19 [2] ba 1e [2] a6 31 }

  condition:
    any of them
}