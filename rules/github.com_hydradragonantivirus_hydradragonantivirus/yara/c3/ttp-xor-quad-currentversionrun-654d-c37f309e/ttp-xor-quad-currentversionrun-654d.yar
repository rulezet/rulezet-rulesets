rule TTP_XOR_QUAD_CurrentVersionRun_654d {
  strings:
    $key_654d = { 36 22 [2] 12 2c [2] 39 00 [2] 17 22 [2] 03 39 [2] 0c 23 [2] 12 3e [2] 10 3f [2] 0b 39 [2] 17 3e [2] 0b 11 }

  condition:
    any of them
}