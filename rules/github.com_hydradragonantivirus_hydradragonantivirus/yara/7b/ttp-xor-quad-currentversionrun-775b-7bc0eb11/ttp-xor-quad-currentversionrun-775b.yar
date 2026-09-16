rule TTP_XOR_QUAD_CurrentVersionRun_775b {
  strings:
    $key_775b = { 24 34 [2] 00 3a [2] 2b 16 [2] 05 34 [2] 11 2f [2] 1e 35 [2] 00 28 [2] 02 29 [2] 19 2f [2] 05 28 [2] 19 07 }

  condition:
    any of them
}