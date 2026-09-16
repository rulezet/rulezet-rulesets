rule TTP_XOR_QUAD_CurrentVersionRun_7540 {
  strings:
    $key_7540 = { 26 2f [2] 02 21 [2] 29 0d [2] 07 2f [2] 13 34 [2] 1c 2e [2] 02 33 [2] 00 32 [2] 1b 34 [2] 07 33 [2] 1b 1c }

  condition:
    any of them
}