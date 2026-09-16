rule TTP_XOR_QUAD_CurrentVersionRun_c80c {
  strings:
    $key_c80c = { 9b 63 [2] bf 6d [2] 94 41 [2] ba 63 [2] ae 78 [2] a1 62 [2] bf 7f [2] bd 7e [2] a6 78 [2] ba 7f [2] a6 50 }

  condition:
    any of them
}