rule TTP_XOR_QUAD_CurrentVersionRun_de5e {
  strings:
    $key_de5e = { 8d 31 [2] a9 3f [2] 82 13 [2] ac 31 [2] b8 2a [2] b7 30 [2] a9 2d [2] ab 2c [2] b0 2a [2] ac 2d [2] b0 02 }

  condition:
    any of them
}