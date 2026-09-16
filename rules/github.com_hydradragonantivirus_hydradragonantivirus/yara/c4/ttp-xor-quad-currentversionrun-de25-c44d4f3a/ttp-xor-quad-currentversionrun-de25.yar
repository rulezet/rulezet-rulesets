rule TTP_XOR_QUAD_CurrentVersionRun_de25 {
  strings:
    $key_de25 = { 8d 4a [2] a9 44 [2] 82 68 [2] ac 4a [2] b8 51 [2] b7 4b [2] a9 56 [2] ab 57 [2] b0 51 [2] ac 56 [2] b0 79 }

  condition:
    any of them
}