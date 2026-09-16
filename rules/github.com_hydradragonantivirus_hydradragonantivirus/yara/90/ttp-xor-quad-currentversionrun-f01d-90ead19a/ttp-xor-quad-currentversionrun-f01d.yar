rule TTP_XOR_QUAD_CurrentVersionRun_f01d {
  strings:
    $key_f01d = { a3 72 [2] 87 7c [2] ac 50 [2] 82 72 [2] 96 69 [2] 99 73 [2] 87 6e [2] 85 6f [2] 9e 69 [2] 82 6e [2] 9e 41 }

  condition:
    any of them
}