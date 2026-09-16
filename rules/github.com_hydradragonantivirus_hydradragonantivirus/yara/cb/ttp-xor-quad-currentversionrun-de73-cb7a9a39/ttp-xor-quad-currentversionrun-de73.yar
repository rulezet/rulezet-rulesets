rule TTP_XOR_QUAD_CurrentVersionRun_de73 {
  strings:
    $key_de73 = { 8d 1c [2] a9 12 [2] 82 3e [2] ac 1c [2] b8 07 [2] b7 1d [2] a9 00 [2] ab 01 [2] b0 07 [2] ac 00 [2] b0 2f }

  condition:
    any of them
}