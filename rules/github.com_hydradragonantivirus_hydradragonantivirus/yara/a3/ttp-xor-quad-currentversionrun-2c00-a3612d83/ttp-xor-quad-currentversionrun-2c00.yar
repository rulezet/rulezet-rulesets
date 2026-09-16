rule TTP_XOR_QUAD_CurrentVersionRun_2c00 {
  strings:
    $key_2c00 = { 7f 6f [2] 5b 61 [2] 70 4d [2] 5e 6f [2] 4a 74 [2] 45 6e [2] 5b 73 [2] 59 72 [2] 42 74 [2] 5e 73 [2] 42 5c }

  condition:
    any of them
}