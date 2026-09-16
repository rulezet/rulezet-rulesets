rule TTP_XOR_QUAD_CurrentVersionRun_de07 {
  strings:
    $key_de07 = { 8d 68 [2] a9 66 [2] 82 4a [2] ac 68 [2] b8 73 [2] b7 69 [2] a9 74 [2] ab 75 [2] b0 73 [2] ac 74 [2] b0 5b }

  condition:
    any of them
}