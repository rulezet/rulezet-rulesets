rule TTP_XOR_QUAD_CurrentVersionRun_f530 {
  strings:
    $key_f530 = { a6 5f [2] 82 51 [2] a9 7d [2] 87 5f [2] 93 44 [2] 9c 5e [2] 82 43 [2] 80 42 [2] 9b 44 [2] 87 43 [2] 9b 6c }

  condition:
    any of them
}