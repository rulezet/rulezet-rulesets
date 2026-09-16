rule TTP_XOR_QUAD_CurrentVersionRun_244d {
  strings:
    $key_244d = { 77 22 [2] 53 2c [2] 78 00 [2] 56 22 [2] 42 39 [2] 4d 23 [2] 53 3e [2] 51 3f [2] 4a 39 [2] 56 3e [2] 4a 11 }

  condition:
    any of them
}