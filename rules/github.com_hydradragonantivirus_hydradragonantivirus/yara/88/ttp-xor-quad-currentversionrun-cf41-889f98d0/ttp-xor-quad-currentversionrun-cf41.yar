rule TTP_XOR_QUAD_CurrentVersionRun_cf41 {
  strings:
    $key_cf41 = { 9c 2e [2] b8 20 [2] 93 0c [2] bd 2e [2] a9 35 [2] a6 2f [2] b8 32 [2] ba 33 [2] a1 35 [2] bd 32 [2] a1 1d }

  condition:
    any of them
}