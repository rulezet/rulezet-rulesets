rule TTP_XOR_QUAD_CurrentVersionRun_d466 {
  strings:
    $key_d466 = { 87 09 [2] a3 07 [2] 88 2b [2] a6 09 [2] b2 12 [2] bd 08 [2] a3 15 [2] a1 14 [2] ba 12 [2] a6 15 [2] ba 3a }

  condition:
    any of them
}