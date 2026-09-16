rule TTP_XOR_QUAD_CurrentVersionRun_0c4d {
  strings:
    $key_0c4d = { 5f 22 [2] 7b 2c [2] 50 00 [2] 7e 22 [2] 6a 39 [2] 65 23 [2] 7b 3e [2] 79 3f [2] 62 39 [2] 7e 3e [2] 62 11 }

  condition:
    any of them
}