rule TTP_XOR_QUAD_CurrentVersionRun_7f30 {
  strings:
    $key_7f30 = { 2c 5f [2] 08 51 [2] 23 7d [2] 0d 5f [2] 19 44 [2] 16 5e [2] 08 43 [2] 0a 42 [2] 11 44 [2] 0d 43 [2] 11 6c }

  condition:
    any of them
}