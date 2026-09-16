rule TTP_XOR_QUAD_CurrentVersionRun_de1d {
  strings:
    $key_de1d = { 8d 72 [2] a9 7c [2] 82 50 [2] ac 72 [2] b8 69 [2] b7 73 [2] a9 6e [2] ab 6f [2] b0 69 [2] ac 6e [2] b0 41 }

  condition:
    any of them
}