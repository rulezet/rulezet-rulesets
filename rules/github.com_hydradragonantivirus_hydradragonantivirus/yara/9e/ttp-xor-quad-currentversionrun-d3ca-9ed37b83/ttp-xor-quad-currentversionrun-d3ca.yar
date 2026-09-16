rule TTP_XOR_QUAD_CurrentVersionRun_d3ca {
  strings:
    $key_d3ca = { 80 a5 [2] a4 ab [2] 8f 87 [2] a1 a5 [2] b5 be [2] ba a4 [2] a4 b9 [2] a6 b8 [2] bd be [2] a1 b9 [2] bd 96 }

  condition:
    any of them
}