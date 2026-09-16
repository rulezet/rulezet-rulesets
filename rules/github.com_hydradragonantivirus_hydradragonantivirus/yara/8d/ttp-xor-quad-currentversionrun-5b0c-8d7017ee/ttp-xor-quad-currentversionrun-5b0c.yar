rule TTP_XOR_QUAD_CurrentVersionRun_5b0c {
  strings:
    $key_5b0c = { 08 63 [2] 2c 6d [2] 07 41 [2] 29 63 [2] 3d 78 [2] 32 62 [2] 2c 7f [2] 2e 7e [2] 35 78 [2] 29 7f [2] 35 50 }

  condition:
    any of them
}