rule TTP_XOR_QUAD_CurrentVersionRun_de7e {
  strings:
    $key_de7e = { 8d 11 [2] a9 1f [2] 82 33 [2] ac 11 [2] b8 0a [2] b7 10 [2] a9 0d [2] ab 0c [2] b0 0a [2] ac 0d [2] b0 22 }

  condition:
    any of them
}