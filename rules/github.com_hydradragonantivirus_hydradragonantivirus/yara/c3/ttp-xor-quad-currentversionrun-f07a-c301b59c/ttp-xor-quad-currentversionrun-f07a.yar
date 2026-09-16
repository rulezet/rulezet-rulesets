rule TTP_XOR_QUAD_CurrentVersionRun_f07a {
  strings:
    $key_f07a = { a3 15 [2] 87 1b [2] ac 37 [2] 82 15 [2] 96 0e [2] 99 14 [2] 87 09 [2] 85 08 [2] 9e 0e [2] 82 09 [2] 9e 26 }

  condition:
    any of them
}