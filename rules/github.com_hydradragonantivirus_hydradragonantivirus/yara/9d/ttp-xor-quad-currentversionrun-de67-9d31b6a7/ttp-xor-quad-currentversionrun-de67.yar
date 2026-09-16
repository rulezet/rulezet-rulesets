rule TTP_XOR_QUAD_CurrentVersionRun_de67 {
  strings:
    $key_de67 = { 8d 08 [2] a9 06 [2] 82 2a [2] ac 08 [2] b8 13 [2] b7 09 [2] a9 14 [2] ab 15 [2] b0 13 [2] ac 14 [2] b0 3b }

  condition:
    any of them
}