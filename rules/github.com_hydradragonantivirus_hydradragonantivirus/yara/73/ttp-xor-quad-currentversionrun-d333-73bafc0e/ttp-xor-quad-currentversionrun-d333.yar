rule TTP_XOR_QUAD_CurrentVersionRun_d333 {
  strings:
    $key_d333 = { 80 5c [2] a4 52 [2] 8f 7e [2] a1 5c [2] b5 47 [2] ba 5d [2] a4 40 [2] a6 41 [2] bd 47 [2] a1 40 [2] bd 6f }

  condition:
    any of them
}