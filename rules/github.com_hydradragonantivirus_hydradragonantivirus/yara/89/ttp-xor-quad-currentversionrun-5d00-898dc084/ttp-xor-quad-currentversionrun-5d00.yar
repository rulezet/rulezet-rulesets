rule TTP_XOR_QUAD_CurrentVersionRun_5d00 {
  strings:
    $key_5d00 = { 0e 6f [2] 2a 61 [2] 01 4d [2] 2f 6f [2] 3b 74 [2] 34 6e [2] 2a 73 [2] 28 72 [2] 33 74 [2] 2f 73 [2] 33 5c }

  condition:
    any of them
}