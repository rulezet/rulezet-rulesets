rule TTP_XOR_QUAD_CurrentVersionRun_de65 {
  strings:
    $key_de65 = { 8d 0a [2] a9 04 [2] 82 28 [2] ac 0a [2] b8 11 [2] b7 0b [2] a9 16 [2] ab 17 [2] b0 11 [2] ac 16 [2] b0 39 }

  condition:
    any of them
}