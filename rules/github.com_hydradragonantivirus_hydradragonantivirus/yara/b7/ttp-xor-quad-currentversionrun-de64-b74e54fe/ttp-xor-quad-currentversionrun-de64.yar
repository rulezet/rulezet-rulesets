rule TTP_XOR_QUAD_CurrentVersionRun_de64 {
  strings:
    $key_de64 = { 8d 0b [2] a9 05 [2] 82 29 [2] ac 0b [2] b8 10 [2] b7 0a [2] a9 17 [2] ab 16 [2] b0 10 [2] ac 17 [2] b0 38 }

  condition:
    any of them
}