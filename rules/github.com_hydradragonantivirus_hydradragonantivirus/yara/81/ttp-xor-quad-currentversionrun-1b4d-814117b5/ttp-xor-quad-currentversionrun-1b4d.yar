rule TTP_XOR_QUAD_CurrentVersionRun_1b4d {
  strings:
    $key_1b4d = { 48 22 [2] 6c 2c [2] 47 00 [2] 69 22 [2] 7d 39 [2] 72 23 [2] 6c 3e [2] 6e 3f [2] 75 39 [2] 69 3e [2] 75 11 }

  condition:
    any of them
}