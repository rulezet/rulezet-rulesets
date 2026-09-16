rule TTP_XOR_QUAD_CurrentVersionRun_484d {
  strings:
    $key_484d = { 1b 22 [2] 3f 2c [2] 14 00 [2] 3a 22 [2] 2e 39 [2] 21 23 [2] 3f 3e [2] 3d 3f [2] 26 39 [2] 3a 3e [2] 26 11 }

  condition:
    any of them
}