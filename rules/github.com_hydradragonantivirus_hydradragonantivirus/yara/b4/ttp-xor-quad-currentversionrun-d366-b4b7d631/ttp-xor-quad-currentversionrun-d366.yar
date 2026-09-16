rule TTP_XOR_QUAD_CurrentVersionRun_d366 {
  strings:
    $key_d366 = { 80 09 [2] a4 07 [2] 8f 2b [2] a1 09 [2] b5 12 [2] ba 08 [2] a4 15 [2] a6 14 [2] bd 12 [2] a1 15 [2] bd 3a }

  condition:
    any of them
}