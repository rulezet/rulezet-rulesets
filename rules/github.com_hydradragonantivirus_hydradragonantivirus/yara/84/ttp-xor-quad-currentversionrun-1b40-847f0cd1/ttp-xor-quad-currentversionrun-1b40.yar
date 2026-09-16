rule TTP_XOR_QUAD_CurrentVersionRun_1b40 {
  strings:
    $key_1b40 = { 48 2f [2] 6c 21 [2] 47 0d [2] 69 2f [2] 7d 34 [2] 72 2e [2] 6c 33 [2] 6e 32 [2] 75 34 [2] 69 33 [2] 75 1c }

  condition:
    any of them
}