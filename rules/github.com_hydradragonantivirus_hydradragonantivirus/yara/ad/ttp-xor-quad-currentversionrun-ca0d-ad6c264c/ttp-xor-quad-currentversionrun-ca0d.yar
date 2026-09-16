rule TTP_XOR_QUAD_CurrentVersionRun_ca0d {
  strings:
    $key_ca0d = { 99 62 [2] bd 6c [2] 96 40 [2] b8 62 [2] ac 79 [2] a3 63 [2] bd 7e [2] bf 7f [2] a4 79 [2] b8 7e [2] a4 51 }

  condition:
    any of them
}