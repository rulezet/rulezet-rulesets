rule TTP_XOR_QUAD_CurrentVersionRun_cf33 {
  strings:
    $key_cf33 = { 9c 5c [2] b8 52 [2] 93 7e [2] bd 5c [2] a9 47 [2] a6 5d [2] b8 40 [2] ba 41 [2] a1 47 [2] bd 40 [2] a1 6f }

  condition:
    any of them
}