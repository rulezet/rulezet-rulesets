rule TTP_XOR_QUAD_CurrentVersionRun_6540 {
  strings:
    $key_6540 = { 36 2f [2] 12 21 [2] 39 0d [2] 17 2f [2] 03 34 [2] 0c 2e [2] 12 33 [2] 10 32 [2] 0b 34 [2] 17 33 [2] 0b 1c }

  condition:
    any of them
}