rule TTP_XOR_QUAD_CurrentVersionRun_de74 {
  strings:
    $key_de74 = { 8d 1b [2] a9 15 [2] 82 39 [2] ac 1b [2] b8 00 [2] b7 1a [2] a9 07 [2] ab 06 [2] b0 00 [2] ac 07 [2] b0 28 }

  condition:
    any of them
}