rule TTP_XOR_QUAD_CurrentVersionRun_4c00 {
  strings:
    $key_4c00 = { 1f 6f [2] 3b 61 [2] 10 4d [2] 3e 6f [2] 2a 74 [2] 25 6e [2] 3b 73 [2] 39 72 [2] 22 74 [2] 3e 73 [2] 22 5c }

  condition:
    any of them
}