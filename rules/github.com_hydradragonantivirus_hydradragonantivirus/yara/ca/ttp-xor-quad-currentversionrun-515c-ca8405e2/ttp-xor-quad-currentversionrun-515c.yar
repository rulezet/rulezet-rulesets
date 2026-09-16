rule TTP_XOR_QUAD_CurrentVersionRun_515c {
  strings:
    $key_515c = { 02 33 [2] 26 3d [2] 0d 11 [2] 23 33 [2] 37 28 [2] 38 32 [2] 26 2f [2] 24 2e [2] 3f 28 [2] 23 2f [2] 3f 00 }

  condition:
    any of them
}