rule TTP_XOR_QUAD_CurrentVersionRun_6900 {
  strings:
    $key_6900 = { 3a 6f [2] 1e 61 [2] 35 4d [2] 1b 6f [2] 0f 74 [2] 00 6e [2] 1e 73 [2] 1c 72 [2] 07 74 [2] 1b 73 [2] 07 5c }

  condition:
    any of them
}