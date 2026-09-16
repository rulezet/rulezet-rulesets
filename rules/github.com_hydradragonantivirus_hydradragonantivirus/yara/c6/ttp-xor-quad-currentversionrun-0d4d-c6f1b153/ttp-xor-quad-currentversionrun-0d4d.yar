rule TTP_XOR_QUAD_CurrentVersionRun_0d4d {
  strings:
    $key_0d4d = { 5e 22 [2] 7a 2c [2] 51 00 [2] 7f 22 [2] 6b 39 [2] 64 23 [2] 7a 3e [2] 78 3f [2] 63 39 [2] 7f 3e [2] 63 11 }

  condition:
    any of them
}