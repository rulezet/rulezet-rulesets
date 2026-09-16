rule TTP_XOR_QUAD_CurrentVersionRun_584d {
  strings:
    $key_584d = { 0b 22 [2] 2f 2c [2] 04 00 [2] 2a 22 [2] 3e 39 [2] 31 23 [2] 2f 3e [2] 2d 3f [2] 36 39 [2] 2a 3e [2] 36 11 }

  condition:
    any of them
}