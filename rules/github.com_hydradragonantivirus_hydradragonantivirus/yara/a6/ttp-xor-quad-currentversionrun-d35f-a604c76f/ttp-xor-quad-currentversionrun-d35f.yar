rule TTP_XOR_QUAD_CurrentVersionRun_d35f {
  strings:
    $key_d35f = { 80 30 [2] a4 3e [2] 8f 12 [2] a1 30 [2] b5 2b [2] ba 31 [2] a4 2c [2] a6 2d [2] bd 2b [2] a1 2c [2] bd 03 }

  condition:
    any of them
}