rule TTP_XOR_QUAD_CurrentVersionRun_7210 {
  strings:
    $key_7210 = { 21 7f [2] 05 71 [2] 2e 5d [2] 00 7f [2] 14 64 [2] 1b 7e [2] 05 63 [2] 07 62 [2] 1c 64 [2] 00 63 [2] 1c 4c }

  condition:
    any of them
}