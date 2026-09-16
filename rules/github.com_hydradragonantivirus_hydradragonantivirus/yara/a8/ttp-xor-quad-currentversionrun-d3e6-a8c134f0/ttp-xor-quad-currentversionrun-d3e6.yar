rule TTP_XOR_QUAD_CurrentVersionRun_d3e6 {
  strings:
    $key_d3e6 = { 80 89 [2] a4 87 [2] 8f ab [2] a1 89 [2] b5 92 [2] ba 88 [2] a4 95 [2] a6 94 [2] bd 92 [2] a1 95 [2] bd ba }

  condition:
    any of them
}