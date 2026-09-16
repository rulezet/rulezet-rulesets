rule TTP_XOR_QUAD_CurrentVersionRun_425c {
  strings:
    $key_425c = { 11 33 [2] 35 3d [2] 1e 11 [2] 30 33 [2] 24 28 [2] 2b 32 [2] 35 2f [2] 37 2e [2] 2c 28 [2] 30 2f [2] 2c 00 }

  condition:
    any of them
}