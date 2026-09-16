rule TTP_XOR_QUAD_CurrentVersionRun_c267 {
  strings:
    $key_c267 = { 91 08 [2] b5 06 [2] 9e 2a [2] b0 08 [2] a4 13 [2] ab 09 [2] b5 14 [2] b7 15 [2] ac 13 [2] b0 14 [2] ac 3b }

  condition:
    any of them
}