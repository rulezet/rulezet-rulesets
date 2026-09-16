rule TTP_XOR_QUAD_CurrentVersionRun_4c4d {
  strings:
    $key_4c4d = { 1f 22 [2] 3b 2c [2] 10 00 [2] 3e 22 [2] 2a 39 [2] 25 23 [2] 3b 3e [2] 39 3f [2] 22 39 [2] 3e 3e [2] 22 11 }

  condition:
    any of them
}