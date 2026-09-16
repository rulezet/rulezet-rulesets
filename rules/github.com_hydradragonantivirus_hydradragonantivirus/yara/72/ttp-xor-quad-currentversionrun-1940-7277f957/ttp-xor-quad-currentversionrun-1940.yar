rule TTP_XOR_QUAD_CurrentVersionRun_1940 {
  strings:
    $key_1940 = { 4a 2f [2] 6e 21 [2] 45 0d [2] 6b 2f [2] 7f 34 [2] 70 2e [2] 6e 33 [2] 6c 32 [2] 77 34 [2] 6b 33 [2] 77 1c }

  condition:
    any of them
}