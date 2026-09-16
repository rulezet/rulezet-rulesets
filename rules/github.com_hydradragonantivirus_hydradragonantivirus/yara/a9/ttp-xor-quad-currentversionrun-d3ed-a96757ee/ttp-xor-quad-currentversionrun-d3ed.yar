rule TTP_XOR_QUAD_CurrentVersionRun_d3ed {
  strings:
    $key_d3ed = { 80 82 [2] a4 8c [2] 8f a0 [2] a1 82 [2] b5 99 [2] ba 83 [2] a4 9e [2] a6 9f [2] bd 99 [2] a1 9e [2] bd b1 }

  condition:
    any of them
}