rule TTP_XOR_QUAD_CurrentVersionRun_de5c {
  strings:
    $key_de5c = { 8d 33 [2] a9 3d [2] 82 11 [2] ac 33 [2] b8 28 [2] b7 32 [2] a9 2f [2] ab 2e [2] b0 28 [2] ac 2f [2] b0 00 }

  condition:
    any of them
}