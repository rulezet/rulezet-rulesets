rule TTP_XOR_QUAD_CurrentVersionRun_ca6d {
  strings:
    $key_ca6d = { 99 02 [2] bd 0c [2] 96 20 [2] b8 02 [2] ac 19 [2] a3 03 [2] bd 1e [2] bf 1f [2] a4 19 [2] b8 1e [2] a4 31 }

  condition:
    any of them
}