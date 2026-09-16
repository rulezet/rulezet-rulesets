rule TTP_XOR_QUAD_CurrentVersionRun_ca10 {
  strings:
    $key_ca10 = { 99 7f [2] bd 71 [2] 96 5d [2] b8 7f [2] ac 64 [2] a3 7e [2] bd 63 [2] bf 62 [2] a4 64 [2] b8 63 [2] a4 4c }

  condition:
    any of them
}