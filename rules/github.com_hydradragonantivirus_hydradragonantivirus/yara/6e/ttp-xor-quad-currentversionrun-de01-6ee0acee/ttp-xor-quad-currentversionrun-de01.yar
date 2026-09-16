rule TTP_XOR_QUAD_CurrentVersionRun_de01 {
  strings:
    $key_de01 = { 8d 6e [2] a9 60 [2] 82 4c [2] ac 6e [2] b8 75 [2] b7 6f [2] a9 72 [2] ab 73 [2] b0 75 [2] ac 72 [2] b0 5d }

  condition:
    any of them
}