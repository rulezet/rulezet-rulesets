rule TTP_XOR_QUAD_CurrentVersionRun_cf6f {
  strings:
    $key_cf6f = { 9c 00 [2] b8 0e [2] 93 22 [2] bd 00 [2] a9 1b [2] a6 01 [2] b8 1c [2] ba 1d [2] a1 1b [2] bd 1c [2] a1 33 }

  condition:
    any of them
}