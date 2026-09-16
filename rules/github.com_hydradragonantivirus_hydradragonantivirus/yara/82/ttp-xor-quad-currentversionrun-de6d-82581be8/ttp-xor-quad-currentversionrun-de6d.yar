rule TTP_XOR_QUAD_CurrentVersionRun_de6d {
  strings:
    $key_de6d = { 8d 02 [2] a9 0c [2] 82 20 [2] ac 02 [2] b8 19 [2] b7 03 [2] a9 1e [2] ab 1f [2] b0 19 [2] ac 1e [2] b0 31 }

  condition:
    any of them
}