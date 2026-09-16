rule TTP_XOR_QUAD_CurrentVersionRun_cfe1 {
  strings:
    $key_cfe1 = { 9c 8e [2] b8 80 [2] 93 ac [2] bd 8e [2] a9 95 [2] a6 8f [2] b8 92 [2] ba 93 [2] a1 95 [2] bd 92 [2] a1 bd }

  condition:
    any of them
}