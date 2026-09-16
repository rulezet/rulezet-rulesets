rule TTP_XOR_QUAD_CurrentVersionRun_ca5d {
  strings:
    $key_ca5d = { 99 32 [2] bd 3c [2] 96 10 [2] b8 32 [2] ac 29 [2] a3 33 [2] bd 2e [2] bf 2f [2] a4 29 [2] b8 2e [2] a4 01 }

  condition:
    any of them
}