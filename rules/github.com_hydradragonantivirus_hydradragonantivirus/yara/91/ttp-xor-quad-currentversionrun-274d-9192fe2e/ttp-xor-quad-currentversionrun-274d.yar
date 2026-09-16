rule TTP_XOR_QUAD_CurrentVersionRun_274d {
  strings:
    $key_274d = { 74 22 [2] 50 2c [2] 7b 00 [2] 55 22 [2] 41 39 [2] 4e 23 [2] 50 3e [2] 52 3f [2] 49 39 [2] 55 3e [2] 49 11 }

  condition:
    any of them
}