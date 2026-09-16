rule TTP_XOR_QUAD_CurrentVersionRun_1540 {
  strings:
    $key_1540 = { 46 2f [2] 62 21 [2] 49 0d [2] 67 2f [2] 73 34 [2] 7c 2e [2] 62 33 [2] 60 32 [2] 7b 34 [2] 67 33 [2] 7b 1c }

  condition:
    any of them
}