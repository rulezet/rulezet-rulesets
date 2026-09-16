rule TTP_XOR_QUAD_CurrentVersionRun_454d {
  strings:
    $key_454d = { 16 22 [2] 32 2c [2] 19 00 [2] 37 22 [2] 23 39 [2] 2c 23 [2] 32 3e [2] 30 3f [2] 2b 39 [2] 37 3e [2] 2b 11 }

  condition:
    any of them
}