rule TTP_XOR_QUAD_CurrentVersionRun_de5f {
  strings:
    $key_de5f = { 8d 30 [2] a9 3e [2] 82 12 [2] ac 30 [2] b8 2b [2] b7 31 [2] a9 2c [2] ab 2d [2] b0 2b [2] ac 2c [2] b0 03 }

  condition:
    any of them
}