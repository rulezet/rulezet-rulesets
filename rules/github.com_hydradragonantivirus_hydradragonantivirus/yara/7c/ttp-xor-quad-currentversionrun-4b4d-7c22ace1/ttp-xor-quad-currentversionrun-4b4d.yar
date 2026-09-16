rule TTP_XOR_QUAD_CurrentVersionRun_4b4d {
  strings:
    $key_4b4d = { 18 22 [2] 3c 2c [2] 17 00 [2] 39 22 [2] 2d 39 [2] 22 23 [2] 3c 3e [2] 3e 3f [2] 25 39 [2] 39 3e [2] 25 11 }

  condition:
    any of them
}