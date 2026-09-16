rule TTP_XOR_QUAD_CurrentVersionRun_454c {
  strings:
    $key_454c = { 16 23 [2] 32 2d [2] 19 01 [2] 37 23 [2] 23 38 [2] 2c 22 [2] 32 3f [2] 30 3e [2] 2b 38 [2] 37 3f [2] 2b 10 }

  condition:
    any of them
}