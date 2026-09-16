rule TTP_XOR_QUAD_CurrentVersionRun_d36f {
  strings:
    $key_d36f = { 80 00 [2] a4 0e [2] 8f 22 [2] a1 00 [2] b5 1b [2] ba 01 [2] a4 1c [2] a6 1d [2] bd 1b [2] a1 1c [2] bd 33 }

  condition:
    any of them
}