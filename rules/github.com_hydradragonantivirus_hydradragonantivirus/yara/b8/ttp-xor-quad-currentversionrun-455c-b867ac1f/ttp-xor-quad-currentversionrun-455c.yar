rule TTP_XOR_QUAD_CurrentVersionRun_455c {
  strings:
    $key_455c = { 16 33 [2] 32 3d [2] 19 11 [2] 37 33 [2] 23 28 [2] 2c 32 [2] 32 2f [2] 30 2e [2] 2b 28 [2] 37 2f [2] 2b 00 }

  condition:
    any of them
}