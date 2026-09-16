rule TTP_XOR_QUAD_CurrentVersionRun_d3e8 {
  strings:
    $key_d3e8 = { 80 87 [2] a4 89 [2] 8f a5 [2] a1 87 [2] b5 9c [2] ba 86 [2] a4 9b [2] a6 9a [2] bd 9c [2] a1 9b [2] bd b4 }

  condition:
    any of them
}