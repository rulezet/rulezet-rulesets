rule TTP_XOR_QUAD_CurrentVersionRun_5840 {
  strings:
    $key_5840 = { 0b 2f [2] 2f 21 [2] 04 0d [2] 2a 2f [2] 3e 34 [2] 31 2e [2] 2f 33 [2] 2d 32 [2] 36 34 [2] 2a 33 [2] 36 1c }

  condition:
    any of them
}