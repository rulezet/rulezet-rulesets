rule TTP_XOR_QUAD_CurrentVersionRun_cae1 {
  strings:
    $key_cae1 = { 99 8e [2] bd 80 [2] 96 ac [2] b8 8e [2] ac 95 [2] a3 8f [2] bd 92 [2] bf 93 [2] a4 95 [2] b8 92 [2] a4 bd }

  condition:
    any of them
}