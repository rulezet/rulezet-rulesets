rule TTP_XOR_QUAD_CurrentVersionRun_cf2d {
  strings:
    $key_cf2d = { 9c 42 [2] b8 4c [2] 93 60 [2] bd 42 [2] a9 59 [2] a6 43 [2] b8 5e [2] ba 5f [2] a1 59 [2] bd 5e [2] a1 71 }

  condition:
    any of them
}