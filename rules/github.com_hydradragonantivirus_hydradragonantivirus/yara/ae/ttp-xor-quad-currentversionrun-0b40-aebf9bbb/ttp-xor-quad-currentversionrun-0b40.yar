rule TTP_XOR_QUAD_CurrentVersionRun_0b40 {
  strings:
    $key_0b40 = { 58 2f [2] 7c 21 [2] 57 0d [2] 79 2f [2] 6d 34 [2] 62 2e [2] 7c 33 [2] 7e 32 [2] 65 34 [2] 79 33 [2] 65 1c }

  condition:
    any of them
}