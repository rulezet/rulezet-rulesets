rule TTP_XOR_QUAD_CurrentVersionRun_7523 {
  strings:
    $key_7523 = { 26 4c [2] 02 42 [2] 29 6e [2] 07 4c [2] 13 57 [2] 1c 4d [2] 02 50 [2] 00 51 [2] 1b 57 [2] 07 50 [2] 1b 7f }

  condition:
    any of them
}