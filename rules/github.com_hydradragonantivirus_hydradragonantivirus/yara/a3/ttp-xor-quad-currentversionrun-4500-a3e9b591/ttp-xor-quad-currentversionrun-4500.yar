rule TTP_XOR_QUAD_CurrentVersionRun_4500 {
  strings:
    $key_4500 = { 16 6f [2] 32 61 [2] 19 4d [2] 37 6f [2] 23 74 [2] 2c 6e [2] 32 73 [2] 30 72 [2] 2b 74 [2] 37 73 [2] 2b 5c }

  condition:
    any of them
}