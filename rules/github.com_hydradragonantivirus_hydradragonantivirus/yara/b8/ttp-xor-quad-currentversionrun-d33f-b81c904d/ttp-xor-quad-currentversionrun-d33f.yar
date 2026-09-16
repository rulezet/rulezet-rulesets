rule TTP_XOR_QUAD_CurrentVersionRun_d33f {
  strings:
    $key_d33f = { 80 50 [2] a4 5e [2] 8f 72 [2] a1 50 [2] b5 4b [2] ba 51 [2] a4 4c [2] a6 4d [2] bd 4b [2] a1 4c [2] bd 63 }

  condition:
    any of them
}