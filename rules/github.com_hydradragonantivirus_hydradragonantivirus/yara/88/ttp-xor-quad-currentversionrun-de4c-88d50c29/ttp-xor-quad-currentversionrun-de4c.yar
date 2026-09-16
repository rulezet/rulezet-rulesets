rule TTP_XOR_QUAD_CurrentVersionRun_de4c {
  strings:
    $key_de4c = { 8d 23 [2] a9 2d [2] 82 01 [2] ac 23 [2] b8 38 [2] b7 22 [2] a9 3f [2] ab 3e [2] b0 38 [2] ac 3f [2] b0 10 }

  condition:
    any of them
}