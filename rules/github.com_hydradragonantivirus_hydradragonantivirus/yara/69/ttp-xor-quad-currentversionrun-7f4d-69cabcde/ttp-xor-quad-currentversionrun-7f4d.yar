rule TTP_XOR_QUAD_CurrentVersionRun_7f4d {
  strings:
    $key_7f4d = { 2c 22 [2] 08 2c [2] 23 00 [2] 0d 22 [2] 19 39 [2] 16 23 [2] 08 3e [2] 0a 3f [2] 11 39 [2] 0d 3e [2] 11 11 }

  condition:
    any of them
}