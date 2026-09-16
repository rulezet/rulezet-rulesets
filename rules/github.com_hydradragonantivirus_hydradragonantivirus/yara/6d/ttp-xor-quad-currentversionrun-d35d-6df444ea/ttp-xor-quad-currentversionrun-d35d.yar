rule TTP_XOR_QUAD_CurrentVersionRun_d35d {
  strings:
    $key_d35d = { 80 32 [2] a4 3c [2] 8f 10 [2] a1 32 [2] b5 29 [2] ba 33 [2] a4 2e [2] a6 2f [2] bd 29 [2] a1 2e [2] bd 01 }

  condition:
    any of them
}