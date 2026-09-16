rule TTP_XOR_QUAD_CurrentVersionRun_de66 {
  strings:
    $key_de66 = { 8d 09 [2] a9 07 [2] 82 2b [2] ac 09 [2] b8 12 [2] b7 08 [2] a9 15 [2] ab 14 [2] b0 12 [2] ac 15 [2] b0 3a }

  condition:
    any of them
}