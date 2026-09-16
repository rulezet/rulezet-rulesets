rule TTP_XOR_QUAD_CurrentVersionRun_de68 {
  strings:
    $key_de68 = { 8d 07 [2] a9 09 [2] 82 25 [2] ac 07 [2] b8 1c [2] b7 06 [2] a9 1b [2] ab 1a [2] b0 1c [2] ac 1b [2] b0 34 }

  condition:
    any of them
}