rule TTP_XOR_QUAD_CurrentVersionRun_7e4d {
  strings:
    $key_7e4d = { 2d 22 [2] 09 2c [2] 22 00 [2] 0c 22 [2] 18 39 [2] 17 23 [2] 09 3e [2] 0b 3f [2] 10 39 [2] 0c 3e [2] 10 11 }

  condition:
    any of them
}