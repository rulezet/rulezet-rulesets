rule TTP_XOR_QUAD_CurrentVersionRun_515d {
  strings:
    $key_515d = { 02 32 [2] 26 3c [2] 0d 10 [2] 23 32 [2] 37 29 [2] 38 33 [2] 26 2e [2] 24 2f [2] 3f 29 [2] 23 2e [2] 3f 01 }

  condition:
    any of them
}