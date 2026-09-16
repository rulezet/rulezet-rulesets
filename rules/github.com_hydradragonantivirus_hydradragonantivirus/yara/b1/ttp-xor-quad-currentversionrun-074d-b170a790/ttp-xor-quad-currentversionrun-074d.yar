rule TTP_XOR_QUAD_CurrentVersionRun_074d {
  strings:
    $key_074d = { 54 22 [2] 70 2c [2] 5b 00 [2] 75 22 [2] 61 39 [2] 6e 23 [2] 70 3e [2] 72 3f [2] 69 39 [2] 75 3e [2] 69 11 }

  condition:
    any of them
}