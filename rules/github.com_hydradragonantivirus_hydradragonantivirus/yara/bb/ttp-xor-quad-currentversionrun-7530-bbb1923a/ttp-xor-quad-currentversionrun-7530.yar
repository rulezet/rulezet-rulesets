rule TTP_XOR_QUAD_CurrentVersionRun_7530 {
  strings:
    $key_7530 = { 26 5f [2] 02 51 [2] 29 7d [2] 07 5f [2] 13 44 [2] 1c 5e [2] 02 43 [2] 00 42 [2] 1b 44 [2] 07 43 [2] 1b 6c }

  condition:
    any of them
}