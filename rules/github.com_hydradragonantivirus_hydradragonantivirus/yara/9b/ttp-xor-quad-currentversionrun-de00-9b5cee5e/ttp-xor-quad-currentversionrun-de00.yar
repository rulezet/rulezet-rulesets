rule TTP_XOR_QUAD_CurrentVersionRun_de00 {
  strings:
    $key_de00 = { 8d 6f [2] a9 61 [2] 82 4d [2] ac 6f [2] b8 74 [2] b7 6e [2] a9 73 [2] ab 72 [2] b0 74 [2] ac 73 [2] b0 5c }

  condition:
    any of them
}