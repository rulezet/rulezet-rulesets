rule TTP_XOR_QUAD_CurrentVersionRun_1f4d {
  strings:
    $key_1f4d = { 4c 22 [2] 68 2c [2] 43 00 [2] 6d 22 [2] 79 39 [2] 76 23 [2] 68 3e [2] 6a 3f [2] 71 39 [2] 6d 3e [2] 71 11 }

  condition:
    any of them
}