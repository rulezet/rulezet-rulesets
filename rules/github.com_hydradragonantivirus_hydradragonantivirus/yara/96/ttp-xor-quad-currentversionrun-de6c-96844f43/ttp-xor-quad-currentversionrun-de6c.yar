rule TTP_XOR_QUAD_CurrentVersionRun_de6c {
  strings:
    $key_de6c = { 8d 03 [2] a9 0d [2] 82 21 [2] ac 03 [2] b8 18 [2] b7 02 [2] a9 1f [2] ab 1e [2] b0 18 [2] ac 1f [2] b0 30 }

  condition:
    any of them
}