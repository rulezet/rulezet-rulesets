rule TTP_XOR_QUAD_CurrentVersionRun_6930 {
  strings:
    $key_6930 = { 3a 5f [2] 1e 51 [2] 35 7d [2] 1b 5f [2] 0f 44 [2] 00 5e [2] 1e 43 [2] 1c 42 [2] 07 44 [2] 1b 43 [2] 07 6c }

  condition:
    any of them
}