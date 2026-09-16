rule TTP_XOR_QUAD_CurrentVersionRun_7f00 {
  strings:
    $key_7f00 = { 2c 6f [2] 08 61 [2] 23 4d [2] 0d 6f [2] 19 74 [2] 16 6e [2] 08 73 [2] 0a 72 [2] 11 74 [2] 0d 73 [2] 11 5c }

  condition:
    any of them
}