rule TTP_XOR_QUAD_CurrentVersionRun_d3f3 {
  strings:
    $key_d3f3 = { 80 9c [2] a4 92 [2] 8f be [2] a1 9c [2] b5 87 [2] ba 9d [2] a4 80 [2] a6 81 [2] bd 87 [2] a1 80 [2] bd af }

  condition:
    any of them
}