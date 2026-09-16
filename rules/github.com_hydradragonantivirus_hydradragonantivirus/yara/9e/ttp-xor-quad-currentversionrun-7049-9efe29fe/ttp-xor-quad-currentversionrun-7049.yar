rule TTP_XOR_QUAD_CurrentVersionRun_7049 {
  strings:
    $key_7049 = { 23 26 [2] 07 28 [2] 2c 04 [2] 02 26 [2] 16 3d [2] 19 27 [2] 07 3a [2] 05 3b [2] 1e 3d [2] 02 3a [2] 1e 15 }

  condition:
    any of them
}