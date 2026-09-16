rule TTP_XOR_QUAD_CurrentVersionRun_7220 {
  strings:
    $key_7220 = { 21 4f [2] 05 41 [2] 2e 6d [2] 00 4f [2] 14 54 [2] 1b 4e [2] 05 53 [2] 07 52 [2] 1c 54 [2] 00 53 [2] 1c 7c }

  condition:
    any of them
}