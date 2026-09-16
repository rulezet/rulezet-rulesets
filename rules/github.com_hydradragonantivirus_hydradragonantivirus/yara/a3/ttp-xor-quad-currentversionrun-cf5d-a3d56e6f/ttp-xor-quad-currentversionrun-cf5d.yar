rule TTP_XOR_QUAD_CurrentVersionRun_cf5d {
  strings:
    $key_cf5d = { 9c 32 [2] b8 3c [2] 93 10 [2] bd 32 [2] a9 29 [2] a6 33 [2] b8 2e [2] ba 2f [2] a1 29 [2] bd 2e [2] a1 01 }

  condition:
    any of them
}