rule TTP_XOR_QUAD_CurrentVersionRun_700b {
  strings:
    $key_700b = { 23 64 [2] 07 6a [2] 2c 46 [2] 02 64 [2] 16 7f [2] 19 65 [2] 07 78 [2] 05 79 [2] 1e 7f [2] 02 78 [2] 1e 57 }

  condition:
    any of them
}