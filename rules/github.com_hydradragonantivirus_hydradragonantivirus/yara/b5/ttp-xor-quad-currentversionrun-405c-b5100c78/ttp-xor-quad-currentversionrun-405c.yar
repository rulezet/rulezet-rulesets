rule TTP_XOR_QUAD_CurrentVersionRun_405c {
  strings:
    $key_405c = { 13 33 [2] 37 3d [2] 1c 11 [2] 32 33 [2] 26 28 [2] 29 32 [2] 37 2f [2] 35 2e [2] 2e 28 [2] 32 2f [2] 2e 00 }

  condition:
    any of them
}