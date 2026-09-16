rule TTP_XOR_QUAD_CurrentVersionRun_1b00 {
  strings:
    $key_1b00 = { 48 6f [2] 6c 61 [2] 47 4d [2] 69 6f [2] 7d 74 [2] 72 6e [2] 6c 73 [2] 6e 72 [2] 75 74 [2] 69 73 [2] 75 5c }

  condition:
    any of them
}