rule TTP_XOR_QUAD_CurrentVersionRun_f760 {
  strings:
    $key_f760 = { a4 0f [2] 80 01 [2] ab 2d [2] 85 0f [2] 91 14 [2] 9e 0e [2] 80 13 [2] 82 12 [2] 99 14 [2] 85 13 [2] 99 3c }

  condition:
    any of them
}