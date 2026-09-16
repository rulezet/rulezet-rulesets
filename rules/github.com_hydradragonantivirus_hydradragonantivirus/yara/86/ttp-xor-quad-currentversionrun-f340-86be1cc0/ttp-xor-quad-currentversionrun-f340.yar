rule TTP_XOR_QUAD_CurrentVersionRun_f340 {
  strings:
    $key_f340 = { a0 2f [2] 84 21 [2] af 0d [2] 81 2f [2] 95 34 [2] 9a 2e [2] 84 33 [2] 86 32 [2] 9d 34 [2] 81 33 [2] 9d 1c }

  condition:
    any of them
}