rule TTP_XOR_QUAD_CurrentVersionRun_5200 {
  strings:
    $key_5200 = { 01 6f [2] 25 61 [2] 0e 4d [2] 20 6f [2] 34 74 [2] 3b 6e [2] 25 73 [2] 27 72 [2] 3c 74 [2] 20 73 [2] 3c 5c }

  condition:
    any of them
}