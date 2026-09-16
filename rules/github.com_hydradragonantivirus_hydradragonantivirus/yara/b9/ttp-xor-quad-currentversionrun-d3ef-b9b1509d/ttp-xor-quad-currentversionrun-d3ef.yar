rule TTP_XOR_QUAD_CurrentVersionRun_d3ef {
  strings:
    $key_d3ef = { 80 80 [2] a4 8e [2] 8f a2 [2] a1 80 [2] b5 9b [2] ba 81 [2] a4 9c [2] a6 9d [2] bd 9b [2] a1 9c [2] bd b3 }

  condition:
    any of them
}