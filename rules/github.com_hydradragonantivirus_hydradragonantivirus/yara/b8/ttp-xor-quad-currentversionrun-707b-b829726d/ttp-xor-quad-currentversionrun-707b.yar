rule TTP_XOR_QUAD_CurrentVersionRun_707b {
  strings:
    $key_707b = { 23 14 [2] 07 1a [2] 2c 36 [2] 02 14 [2] 16 0f [2] 19 15 [2] 07 08 [2] 05 09 [2] 1e 0f [2] 02 08 [2] 1e 27 }

  condition:
    any of them
}