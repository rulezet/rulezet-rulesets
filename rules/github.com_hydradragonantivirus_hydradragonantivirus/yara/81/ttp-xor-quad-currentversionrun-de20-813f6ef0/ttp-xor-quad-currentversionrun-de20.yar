rule TTP_XOR_QUAD_CurrentVersionRun_de20 {
  strings:
    $key_de20 = { 8d 4f [2] a9 41 [2] 82 6d [2] ac 4f [2] b8 54 [2] b7 4e [2] a9 53 [2] ab 52 [2] b0 54 [2] ac 53 [2] b0 7c }

  condition:
    any of them
}