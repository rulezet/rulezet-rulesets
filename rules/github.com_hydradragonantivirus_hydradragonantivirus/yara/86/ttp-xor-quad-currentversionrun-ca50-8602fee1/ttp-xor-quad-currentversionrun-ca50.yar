rule TTP_XOR_QUAD_CurrentVersionRun_ca50 {
  strings:
    $key_ca50 = { 99 3f [2] bd 31 [2] 96 1d [2] b8 3f [2] ac 24 [2] a3 3e [2] bd 23 [2] bf 22 [2] a4 24 [2] b8 23 [2] a4 0c }

  condition:
    any of them
}