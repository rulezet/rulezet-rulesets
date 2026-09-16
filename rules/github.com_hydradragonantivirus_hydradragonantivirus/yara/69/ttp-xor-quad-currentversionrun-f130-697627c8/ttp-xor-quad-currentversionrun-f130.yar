rule TTP_XOR_QUAD_CurrentVersionRun_f130 {
  strings:
    $key_f130 = { a2 5f [2] 86 51 [2] ad 7d [2] 83 5f [2] 97 44 [2] 98 5e [2] 86 43 [2] 84 42 [2] 9f 44 [2] 83 43 [2] 9f 6c }

  condition:
    any of them
}