rule TTP_XOR_QUAD_CurrentVersionRun_7f1d {
  strings:
    $key_7f1d = { 2c 72 [2] 08 7c [2] 23 50 [2] 0d 72 [2] 19 69 [2] 16 73 [2] 08 6e [2] 0a 6f [2] 11 69 [2] 0d 6e [2] 11 41 }

  condition:
    any of them
}