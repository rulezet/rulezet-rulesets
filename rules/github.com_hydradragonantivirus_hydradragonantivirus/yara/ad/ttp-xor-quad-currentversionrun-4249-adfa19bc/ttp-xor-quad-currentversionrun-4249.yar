rule TTP_XOR_QUAD_CurrentVersionRun_4249 {
  strings:
    $key_4249 = { 11 26 [2] 35 28 [2] 1e 04 [2] 30 26 [2] 24 3d [2] 2b 27 [2] 35 3a [2] 37 3b [2] 2c 3d [2] 30 3a [2] 2c 15 }

  condition:
    any of them
}