rule TTP_XOR_QUAD_CurrentVersionRun_d441 {
  strings:
    $key_d441 = { 87 2e [2] a3 20 [2] 88 0c [2] a6 2e [2] b2 35 [2] bd 2f [2] a3 32 [2] a1 33 [2] ba 35 [2] a6 32 [2] ba 1d }

  condition:
    any of them
}