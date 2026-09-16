rule TTP_XOR_QUAD_CurrentVersionRun_de23 {
  strings:
    $key_de23 = { 8d 4c [2] a9 42 [2] 82 6e [2] ac 4c [2] b8 57 [2] b7 4d [2] a9 50 [2] ab 51 [2] b0 57 [2] ac 50 [2] b0 7f }

  condition:
    any of them
}