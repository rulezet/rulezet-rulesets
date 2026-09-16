rule TTP_XOR_QUAD_CurrentVersionRun_7200 {
  strings:
    $key_7200 = { 21 6f [2] 05 61 [2] 2e 4d [2] 00 6f [2] 14 74 [2] 1b 6e [2] 05 73 [2] 07 72 [2] 1c 74 [2] 00 73 [2] 1c 5c }

  condition:
    any of them
}