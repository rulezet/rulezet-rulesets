rule TTP_XOR_QUAD_CurrentVersionRun_f000 {
  strings:
    $key_f000 = { a3 6f [2] 87 61 [2] ac 4d [2] 82 6f [2] 96 74 [2] 99 6e [2] 87 73 [2] 85 72 [2] 9e 74 [2] 82 73 [2] 9e 5c }

  condition:
    any of them
}