rule TTP_XOR_QUAD_CurrentVersionRun_de41 {
  strings:
    $key_de41 = { 8d 2e [2] a9 20 [2] 82 0c [2] ac 2e [2] b8 35 [2] b7 2f [2] a9 32 [2] ab 33 [2] b0 35 [2] ac 32 [2] b0 1d }

  condition:
    any of them
}