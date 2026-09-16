rule TTP_XOR_QUAD_CurrentVersionRun_514d {
  strings:
    $key_514d = { 02 22 [2] 26 2c [2] 0d 00 [2] 23 22 [2] 37 39 [2] 38 23 [2] 26 3e [2] 24 3f [2] 3f 39 [2] 23 3e [2] 3f 11 }

  condition:
    any of them
}