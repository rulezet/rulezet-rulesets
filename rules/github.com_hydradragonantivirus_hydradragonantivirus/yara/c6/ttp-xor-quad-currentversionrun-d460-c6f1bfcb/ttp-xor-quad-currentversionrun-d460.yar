rule TTP_XOR_QUAD_CurrentVersionRun_d460 {
  strings:
    $key_d460 = { 87 0f [2] a3 01 [2] 88 2d [2] a6 0f [2] b2 14 [2] bd 0e [2] a3 13 [2] a1 12 [2] ba 14 [2] a6 13 [2] ba 3c }

  condition:
    any of them
}