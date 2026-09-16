rule TTP_XOR_QUAD_CurrentVersionRun_de76 {
  strings:
    $key_de76 = { 8d 19 [2] a9 17 [2] 82 3b [2] ac 19 [2] b8 02 [2] b7 18 [2] a9 05 [2] ab 04 [2] b0 02 [2] ac 05 [2] b0 2a }

  condition:
    any of them
}