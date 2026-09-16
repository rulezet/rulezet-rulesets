rule TTP_XOR_QUAD_CurrentVersionRun_d45f {
  strings:
    $key_d45f = { 87 30 [2] a3 3e [2] 88 12 [2] a6 30 [2] b2 2b [2] bd 31 [2] a3 2c [2] a1 2d [2] ba 2b [2] a6 2c [2] ba 03 }

  condition:
    any of them
}