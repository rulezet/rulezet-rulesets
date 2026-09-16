rule TTP_XOR_QUAD_CurrentVersionRun_d3f0 {
  strings:
    $key_d3f0 = { 80 9f [2] a4 91 [2] 8f bd [2] a1 9f [2] b5 84 [2] ba 9e [2] a4 83 [2] a6 82 [2] bd 84 [2] a1 83 [2] bd ac }

  condition:
    any of them
}