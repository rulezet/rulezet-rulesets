rule TTP_XOR_QUAD_CurrentVersionRun_7761 {
  strings:
    $key_7761 = { 24 0e [2] 00 00 [2] 2b 2c [2] 05 0e [2] 11 15 [2] 1e 0f [2] 00 12 [2] 02 13 [2] 19 15 [2] 05 12 [2] 19 3d }

  condition:
    any of them
}