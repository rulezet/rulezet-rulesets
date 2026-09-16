rule TTP_XOR_QUAD_CurrentVersionRun_044d {
  strings:
    $key_044d = { 57 22 [2] 73 2c [2] 58 00 [2] 76 22 [2] 62 39 [2] 6d 23 [2] 73 3e [2] 71 3f [2] 6a 39 [2] 76 3e [2] 6a 11 }

  condition:
    any of them
}