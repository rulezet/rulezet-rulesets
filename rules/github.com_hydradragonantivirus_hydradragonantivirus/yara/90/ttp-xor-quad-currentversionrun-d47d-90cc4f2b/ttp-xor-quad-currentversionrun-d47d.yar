rule TTP_XOR_QUAD_CurrentVersionRun_d47d {
  strings:
    $key_d47d = { 87 12 [2] a3 1c [2] 88 30 [2] a6 12 [2] b2 09 [2] bd 13 [2] a3 0e [2] a1 0f [2] ba 09 [2] a6 0e [2] ba 21 }

  condition:
    any of them
}