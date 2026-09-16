rule TTP_XOR_QUAD_CurrentVersionRun_7030 {
  strings:
    $key_7030 = { 23 5f [2] 07 51 [2] 2c 7d [2] 02 5f [2] 16 44 [2] 19 5e [2] 07 43 [2] 05 42 [2] 1e 44 [2] 02 43 [2] 1e 6c }

  condition:
    any of them
}