rule TTP_XOR_QUAD_CurrentVersionRun_7d4d {
  strings:
    $key_7d4d = { 2e 22 [2] 0a 2c [2] 21 00 [2] 0f 22 [2] 1b 39 [2] 14 23 [2] 0a 3e [2] 08 3f [2] 13 39 [2] 0f 3e [2] 13 11 }

  condition:
    any of them
}