rule TTP_XOR_QUAD_CurrentVersionRun_d4e1 {
  strings:
    $key_d4e1 = { 87 8e [2] a3 80 [2] 88 ac [2] a6 8e [2] b2 95 [2] bd 8f [2] a3 92 [2] a1 93 [2] ba 95 [2] a6 92 [2] ba bd }

  condition:
    any of them
}