rule TTP_XOR_QUAD_CurrentVersionRun_7026 {
  strings:
    $key_7026 = { 23 49 [2] 07 47 [2] 2c 6b [2] 02 49 [2] 16 52 [2] 19 48 [2] 07 55 [2] 05 54 [2] 1e 52 [2] 02 55 [2] 1e 7a }

  condition:
    any of them
}