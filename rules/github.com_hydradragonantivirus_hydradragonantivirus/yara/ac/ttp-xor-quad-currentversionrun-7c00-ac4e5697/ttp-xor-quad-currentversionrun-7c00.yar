rule TTP_XOR_QUAD_CurrentVersionRun_7c00 {
  strings:
    $key_7c00 = { 2f 6f [2] 0b 61 [2] 20 4d [2] 0e 6f [2] 1a 74 [2] 15 6e [2] 0b 73 [2] 09 72 [2] 12 74 [2] 0e 73 [2] 12 5c }

  condition:
    any of them
}