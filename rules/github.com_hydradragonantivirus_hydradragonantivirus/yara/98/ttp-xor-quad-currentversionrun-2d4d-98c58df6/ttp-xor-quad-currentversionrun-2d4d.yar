rule TTP_XOR_QUAD_CurrentVersionRun_2d4d {
  strings:
    $key_2d4d = { 7e 22 [2] 5a 2c [2] 71 00 [2] 5f 22 [2] 4b 39 [2] 44 23 [2] 5a 3e [2] 58 3f [2] 43 39 [2] 5f 3e [2] 43 11 }

  condition:
    any of them
}