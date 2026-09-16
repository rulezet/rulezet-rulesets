rule TTP_XOR_QUAD_CurrentVersionRun_427b {
  strings:
    $key_427b = { 11 14 [2] 35 1a [2] 1e 36 [2] 30 14 [2] 24 0f [2] 2b 15 [2] 35 08 [2] 37 09 [2] 2c 0f [2] 30 08 [2] 2c 27 }

  condition:
    any of them
}