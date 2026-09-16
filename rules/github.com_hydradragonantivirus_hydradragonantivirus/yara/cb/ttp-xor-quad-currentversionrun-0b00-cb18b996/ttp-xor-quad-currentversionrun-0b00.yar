rule TTP_XOR_QUAD_CurrentVersionRun_0b00 {
  strings:
    $key_0b00 = { 58 6f [2] 7c 61 [2] 57 4d [2] 79 6f [2] 6d 74 [2] 62 6e [2] 7c 73 [2] 7e 72 [2] 65 74 [2] 79 73 [2] 65 5c }

  condition:
    any of them
}