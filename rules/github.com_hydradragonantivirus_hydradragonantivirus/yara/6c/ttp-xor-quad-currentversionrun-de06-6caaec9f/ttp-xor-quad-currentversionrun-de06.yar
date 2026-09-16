rule TTP_XOR_QUAD_CurrentVersionRun_de06 {
  strings:
    $key_de06 = { 8d 69 [2] a9 67 [2] 82 4b [2] ac 69 [2] b8 72 [2] b7 68 [2] a9 75 [2] ab 74 [2] b0 72 [2] ac 75 [2] b0 5a }

  condition:
    any of them
}