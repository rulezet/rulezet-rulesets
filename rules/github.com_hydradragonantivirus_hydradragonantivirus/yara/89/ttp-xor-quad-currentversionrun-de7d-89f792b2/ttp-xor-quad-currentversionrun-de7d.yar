rule TTP_XOR_QUAD_CurrentVersionRun_de7d {
  strings:
    $key_de7d = { 8d 12 [2] a9 1c [2] 82 30 [2] ac 12 [2] b8 09 [2] b7 13 [2] a9 0e [2] ab 0f [2] b0 09 [2] ac 0e [2] b0 21 }

  condition:
    any of them
}