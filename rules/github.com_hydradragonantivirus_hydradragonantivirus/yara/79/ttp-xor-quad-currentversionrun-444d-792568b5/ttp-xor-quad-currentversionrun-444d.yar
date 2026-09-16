rule TTP_XOR_QUAD_CurrentVersionRun_444d {
  strings:
    $key_444d = { 17 22 [2] 33 2c [2] 18 00 [2] 36 22 [2] 22 39 [2] 2d 23 [2] 33 3e [2] 31 3f [2] 2a 39 [2] 36 3e [2] 2a 11 }

  condition:
    any of them
}