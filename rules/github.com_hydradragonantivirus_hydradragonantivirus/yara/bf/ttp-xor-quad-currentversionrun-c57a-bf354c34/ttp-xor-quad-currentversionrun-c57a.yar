rule TTP_XOR_QUAD_CurrentVersionRun_c57a {
  strings:
    $key_c57a = { 96 15 [2] b2 1b [2] 99 37 [2] b7 15 [2] a3 0e [2] ac 14 [2] b2 09 [2] b0 08 [2] ab 0e [2] b7 09 [2] ab 26 }

  condition:
    any of them
}