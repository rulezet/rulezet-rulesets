rule TTP_XOR_QUAD_CurrentVersionRun_de33 {
  strings:
    $key_de33 = { 8d 5c [2] a9 52 [2] 82 7e [2] ac 5c [2] b8 47 [2] b7 5d [2] a9 40 [2] ab 41 [2] b0 47 [2] ac 40 [2] b0 6f }

  condition:
    any of them
}