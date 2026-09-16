rule TTP_XOR_QUAD_CurrentVersionRun_de5d {
  strings:
    $key_de5d = { 8d 32 [2] a9 3c [2] 82 10 [2] ac 32 [2] b8 29 [2] b7 33 [2] a9 2e [2] ab 2f [2] b0 29 [2] ac 2e [2] b0 01 }

  condition:
    any of them
}