rule TTP_XOR_QUAD_CurrentVersionRun_3e4d {
  strings:
    $key_3e4d = { 6d 22 [2] 49 2c [2] 62 00 [2] 4c 22 [2] 58 39 [2] 57 23 [2] 49 3e [2] 4b 3f [2] 50 39 [2] 4c 3e [2] 50 11 }

  condition:
    any of them
}