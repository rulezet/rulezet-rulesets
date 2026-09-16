rule TTP_XOR_QUAD_CurrentVersionRun_f730 {
  strings:
    $key_f730 = { a4 5f [2] 80 51 [2] ab 7d [2] 85 5f [2] 91 44 [2] 9e 5e [2] 80 43 [2] 82 42 [2] 99 44 [2] 85 43 [2] 99 6c }

  condition:
    any of them
}