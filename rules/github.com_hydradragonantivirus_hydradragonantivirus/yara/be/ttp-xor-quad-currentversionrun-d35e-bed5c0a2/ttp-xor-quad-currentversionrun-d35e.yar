rule TTP_XOR_QUAD_CurrentVersionRun_d35e {
  strings:
    $key_d35e = { 80 31 [2] a4 3f [2] 8f 13 [2] a1 31 [2] b5 2a [2] ba 30 [2] a4 2d [2] a6 2c [2] bd 2a [2] a1 2d [2] bd 02 }

  condition:
    any of them
}