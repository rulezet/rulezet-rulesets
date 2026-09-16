rule TTP_XOR_QUAD_CurrentVersionRun_d32c {
  strings:
    $key_d32c = { 80 43 [2] a4 4d [2] 8f 61 [2] a1 43 [2] b5 58 [2] ba 42 [2] a4 5f [2] a6 5e [2] bd 58 [2] a1 5f [2] bd 70 }

  condition:
    any of them
}