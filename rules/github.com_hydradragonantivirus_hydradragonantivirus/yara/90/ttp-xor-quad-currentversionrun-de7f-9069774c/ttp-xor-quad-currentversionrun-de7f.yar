rule TTP_XOR_QUAD_CurrentVersionRun_de7f {
  strings:
    $key_de7f = { 8d 10 [2] a9 1e [2] 82 32 [2] ac 10 [2] b8 0b [2] b7 11 [2] a9 0c [2] ab 0d [2] b0 0b [2] ac 0c [2] b0 23 }

  condition:
    any of them
}