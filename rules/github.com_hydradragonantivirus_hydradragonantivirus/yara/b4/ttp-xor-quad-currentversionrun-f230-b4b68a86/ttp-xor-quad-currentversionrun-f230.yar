rule TTP_XOR_QUAD_CurrentVersionRun_f230 {
  strings:
    $key_f230 = { a1 5f [2] 85 51 [2] ae 7d [2] 80 5f [2] 94 44 [2] 9b 5e [2] 85 43 [2] 87 42 [2] 9c 44 [2] 80 43 [2] 9c 6c }

  condition:
    any of them
}