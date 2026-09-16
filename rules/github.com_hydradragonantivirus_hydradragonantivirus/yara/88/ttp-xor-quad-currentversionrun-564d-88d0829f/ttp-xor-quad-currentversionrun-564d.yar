rule TTP_XOR_QUAD_CurrentVersionRun_564d {
  strings:
    $key_564d = { 05 22 [2] 21 2c [2] 0a 00 [2] 24 22 [2] 30 39 [2] 3f 23 [2] 21 3e [2] 23 3f [2] 38 39 [2] 24 3e [2] 38 11 }

  condition:
    any of them
}