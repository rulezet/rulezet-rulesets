rule TTP_XOR_QUAD_CurrentVersionRun_d440 {
  strings:
    $key_d440 = { 87 2f [2] a3 21 [2] 88 0d [2] a6 2f [2] b2 34 [2] bd 2e [2] a3 33 [2] a1 32 [2] ba 34 [2] a6 33 [2] ba 1c }

  condition:
    any of them
}