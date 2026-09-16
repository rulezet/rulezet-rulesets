rule TTP_XOR_QUAD_CurrentVersionRun_f27a {
  strings:
    $key_f27a = { a1 15 [2] 85 1b [2] ae 37 [2] 80 15 [2] 94 0e [2] 9b 14 [2] 85 09 [2] 87 08 [2] 9c 0e [2] 80 09 [2] 9c 26 }

  condition:
    any of them
}