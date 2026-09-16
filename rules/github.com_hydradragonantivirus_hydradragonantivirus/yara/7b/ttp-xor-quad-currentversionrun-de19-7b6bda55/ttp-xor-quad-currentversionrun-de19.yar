rule TTP_XOR_QUAD_CurrentVersionRun_de19 {
  strings:
    $key_de19 = { 8d 76 [2] a9 78 [2] 82 54 [2] ac 76 [2] b8 6d [2] b7 77 [2] a9 6a [2] ab 6b [2] b0 6d [2] ac 6a [2] b0 45 }

  condition:
    any of them
}