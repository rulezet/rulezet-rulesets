rule TTP_XOR_QUAD_CurrentVersionRun_ca6c {
  strings:
    $key_ca6c = { 99 03 [2] bd 0d [2] 96 21 [2] b8 03 [2] ac 18 [2] a3 02 [2] bd 1f [2] bf 1e [2] a4 18 [2] b8 1f [2] a4 30 }

  condition:
    any of them
}