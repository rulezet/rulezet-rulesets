rule TTP_XOR_QUAD_CurrentVersionRun_707c {
  strings:
    $key_707c = { 23 13 [2] 07 1d [2] 2c 31 [2] 02 13 [2] 16 08 [2] 19 12 [2] 07 0f [2] 05 0e [2] 1e 08 [2] 02 0f [2] 1e 20 }

  condition:
    any of them
}