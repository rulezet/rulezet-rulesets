rule TTP_XOR_QUAD_CurrentVersionRun_7900 {
  strings:
    $key_7900 = { 2a 6f [2] 0e 61 [2] 25 4d [2] 0b 6f [2] 1f 74 [2] 10 6e [2] 0e 73 [2] 0c 72 [2] 17 74 [2] 0b 73 [2] 17 5c }

  condition:
    any of them
}