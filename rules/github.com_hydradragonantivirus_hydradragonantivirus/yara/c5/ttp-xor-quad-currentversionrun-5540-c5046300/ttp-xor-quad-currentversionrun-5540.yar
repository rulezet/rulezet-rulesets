rule TTP_XOR_QUAD_CurrentVersionRun_5540 {
  strings:
    $key_5540 = { 06 2f [2] 22 21 [2] 09 0d [2] 27 2f [2] 33 34 [2] 3c 2e [2] 22 33 [2] 20 32 [2] 3b 34 [2] 27 33 [2] 3b 1c }

  condition:
    any of them
}