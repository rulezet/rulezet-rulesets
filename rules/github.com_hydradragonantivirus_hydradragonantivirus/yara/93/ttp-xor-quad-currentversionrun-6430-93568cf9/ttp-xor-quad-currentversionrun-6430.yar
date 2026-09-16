rule TTP_XOR_QUAD_CurrentVersionRun_6430 {
  strings:
    $key_6430 = { 37 5f [2] 13 51 [2] 38 7d [2] 16 5f [2] 02 44 [2] 0d 5e [2] 13 43 [2] 11 42 [2] 0a 44 [2] 16 43 [2] 0a 6c }

  condition:
    any of them
}