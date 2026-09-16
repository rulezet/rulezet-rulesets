rule TTP_XOR_QUAD_CurrentVersionRun_de18 {
  strings:
    $key_de18 = { 8d 77 [2] a9 79 [2] 82 55 [2] ac 77 [2] b8 6c [2] b7 76 [2] a9 6b [2] ab 6a [2] b0 6c [2] ac 6b [2] b0 44 }

  condition:
    any of them
}