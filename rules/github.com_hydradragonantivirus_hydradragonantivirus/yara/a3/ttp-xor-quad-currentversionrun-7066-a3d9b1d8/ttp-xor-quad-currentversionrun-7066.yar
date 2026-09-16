rule TTP_XOR_QUAD_CurrentVersionRun_7066 {
  strings:
    $key_7066 = { 23 09 [2] 07 07 [2] 2c 2b [2] 02 09 [2] 16 12 [2] 19 08 [2] 07 15 [2] 05 14 [2] 1e 12 [2] 02 15 [2] 1e 3a }

  condition:
    any of them
}