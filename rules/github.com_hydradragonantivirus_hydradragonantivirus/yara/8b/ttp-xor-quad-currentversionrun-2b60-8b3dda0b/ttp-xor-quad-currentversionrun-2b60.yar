rule TTP_XOR_QUAD_CurrentVersionRun_2b60 {
  strings:
    $key_2b60 = { 78 0f [2] 5c 01 [2] 77 2d [2] 59 0f [2] 4d 14 [2] 42 0e [2] 5c 13 [2] 5e 12 [2] 45 14 [2] 59 13 [2] 45 3c }

  condition:
    any of them
}