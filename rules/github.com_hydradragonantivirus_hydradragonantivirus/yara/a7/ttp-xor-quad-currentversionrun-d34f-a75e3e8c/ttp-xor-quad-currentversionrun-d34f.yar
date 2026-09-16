rule TTP_XOR_QUAD_CurrentVersionRun_d34f {
  strings:
    $key_d34f = { 80 20 [2] a4 2e [2] 8f 02 [2] a1 20 [2] b5 3b [2] ba 21 [2] a4 3c [2] a6 3d [2] bd 3b [2] a1 3c [2] bd 13 }

  condition:
    any of them
}