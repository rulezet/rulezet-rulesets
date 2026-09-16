rule TTP_XOR_QUAD_CurrentVersionRun_de60 {
  strings:
    $key_de60 = { 8d 0f [2] a9 01 [2] 82 2d [2] ac 0f [2] b8 14 [2] b7 0e [2] a9 13 [2] ab 12 [2] b0 14 [2] ac 13 [2] b0 3c }

  condition:
    any of them
}