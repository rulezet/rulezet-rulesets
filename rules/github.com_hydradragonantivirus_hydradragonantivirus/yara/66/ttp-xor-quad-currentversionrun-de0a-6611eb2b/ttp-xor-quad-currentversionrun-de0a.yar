rule TTP_XOR_QUAD_CurrentVersionRun_de0a {
  strings:
    $key_de0a = { 8d 65 [2] a9 6b [2] 82 47 [2] ac 65 [2] b8 7e [2] b7 64 [2] a9 79 [2] ab 78 [2] b0 7e [2] ac 79 [2] b0 56 }

  condition:
    any of them
}