rule TTP_XOR_QUAD_CurrentVersionRun_2b40 {
  strings:
    $key_2b40 = { 78 2f [2] 5c 21 [2] 77 0d [2] 59 2f [2] 4d 34 [2] 42 2e [2] 5c 33 [2] 5e 32 [2] 45 34 [2] 59 33 [2] 45 1c }

  condition:
    any of them
}