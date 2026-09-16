rule TTP_XOR_QUAD_CurrentVersionRun_705c {
  strings:
    $key_705c = { 23 33 [2] 07 3d [2] 2c 11 [2] 02 33 [2] 16 28 [2] 19 32 [2] 07 2f [2] 05 2e [2] 1e 28 [2] 02 2f [2] 1e 00 }

  condition:
    any of them
}