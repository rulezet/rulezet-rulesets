rule TTP_XOR_QUAD_CurrentVersionRun_5e30 {
  strings:
    $key_5e30 = { 0d 5f [2] 29 51 [2] 02 7d [2] 2c 5f [2] 38 44 [2] 37 5e [2] 29 43 [2] 2b 42 [2] 30 44 [2] 2c 43 [2] 30 6c }

  condition:
    any of them
}