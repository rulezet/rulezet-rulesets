rule TTP_XOR_QUAD_CurrentVersionRun_d3f2 {
  strings:
    $key_d3f2 = { 80 9d [2] a4 93 [2] 8f bf [2] a1 9d [2] b5 86 [2] ba 9c [2] a4 81 [2] a6 80 [2] bd 86 [2] a1 81 [2] bd ae }

  condition:
    any of them
}