rule TTP_XOR_QUAD_CurrentVersionRun_de39 {
  strings:
    $key_de39 = { 8d 56 [2] a9 58 [2] 82 74 [2] ac 56 [2] b8 4d [2] b7 57 [2] a9 4a [2] ab 4b [2] b0 4d [2] ac 4a [2] b0 65 }

  condition:
    any of them
}