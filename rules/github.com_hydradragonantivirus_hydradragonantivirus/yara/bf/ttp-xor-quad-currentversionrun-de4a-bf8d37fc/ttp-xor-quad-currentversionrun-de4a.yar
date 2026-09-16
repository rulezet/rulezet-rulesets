rule TTP_XOR_QUAD_CurrentVersionRun_de4a {
  strings:
    $key_de4a = { 8d 25 [2] a9 2b [2] 82 07 [2] ac 25 [2] b8 3e [2] b7 24 [2] a9 39 [2] ab 38 [2] b0 3e [2] ac 39 [2] b0 16 }

  condition:
    any of them
}