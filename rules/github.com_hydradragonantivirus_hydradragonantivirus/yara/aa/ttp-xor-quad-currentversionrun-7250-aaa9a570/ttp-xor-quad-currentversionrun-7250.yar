rule TTP_XOR_QUAD_CurrentVersionRun_7250 {
  strings:
    $key_7250 = { 21 3f [2] 05 31 [2] 2e 1d [2] 00 3f [2] 14 24 [2] 1b 3e [2] 05 23 [2] 07 22 [2] 1c 24 [2] 00 23 [2] 1c 0c }

  condition:
    any of them
}