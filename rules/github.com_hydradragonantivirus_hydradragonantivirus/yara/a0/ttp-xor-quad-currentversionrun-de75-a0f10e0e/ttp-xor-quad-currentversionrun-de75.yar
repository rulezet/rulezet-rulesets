rule TTP_XOR_QUAD_CurrentVersionRun_de75 {
  strings:
    $key_de75 = { 8d 1a [2] a9 14 [2] 82 38 [2] ac 1a [2] b8 01 [2] b7 1b [2] a9 06 [2] ab 07 [2] b0 01 [2] ac 06 [2] b0 29 }

  condition:
    any of them
}