rule TTP_XOR_QUAD_CurrentVersionRun_7f40 {
  strings:
    $key_7f40 = { 2c 2f [2] 08 21 [2] 23 0d [2] 0d 2f [2] 19 34 [2] 16 2e [2] 08 33 [2] 0a 32 [2] 11 34 [2] 0d 33 [2] 11 1c }

  condition:
    any of them
}