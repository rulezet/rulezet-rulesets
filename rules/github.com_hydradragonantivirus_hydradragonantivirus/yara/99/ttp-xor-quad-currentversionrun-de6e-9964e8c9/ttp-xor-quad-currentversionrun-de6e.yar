rule TTP_XOR_QUAD_CurrentVersionRun_de6e {
  strings:
    $key_de6e = { 8d 01 [2] a9 0f [2] 82 23 [2] ac 01 [2] b8 1a [2] b7 00 [2] a9 1d [2] ab 1c [2] b0 1a [2] ac 1d [2] b0 32 }

  condition:
    any of them
}