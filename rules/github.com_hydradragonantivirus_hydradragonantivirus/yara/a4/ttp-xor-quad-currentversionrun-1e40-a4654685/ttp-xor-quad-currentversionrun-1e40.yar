rule TTP_XOR_QUAD_CurrentVersionRun_1e40 {
  strings:
    $key_1e40 = { 4d 2f [2] 69 21 [2] 42 0d [2] 6c 2f [2] 78 34 [2] 77 2e [2] 69 33 [2] 6b 32 [2] 70 34 [2] 6c 33 [2] 70 1c }

  condition:
    any of them
}