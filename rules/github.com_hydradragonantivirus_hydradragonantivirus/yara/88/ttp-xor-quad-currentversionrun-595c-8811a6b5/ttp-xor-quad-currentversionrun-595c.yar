rule TTP_XOR_QUAD_CurrentVersionRun_595c {
  strings:
    $key_595c = { 0a 33 [2] 2e 3d [2] 05 11 [2] 2b 33 [2] 3f 28 [2] 30 32 [2] 2e 2f [2] 2c 2e [2] 37 28 [2] 2b 2f [2] 37 00 }

  condition:
    any of them
}