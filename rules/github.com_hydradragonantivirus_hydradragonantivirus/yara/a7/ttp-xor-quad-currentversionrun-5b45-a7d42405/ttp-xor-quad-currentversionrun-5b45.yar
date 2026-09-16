rule TTP_XOR_QUAD_CurrentVersionRun_5b45 {
  strings:
    $key_5b45 = { 08 2a [2] 2c 24 [2] 07 08 [2] 29 2a [2] 3d 31 [2] 32 2b [2] 2c 36 [2] 2e 37 [2] 35 31 [2] 29 36 [2] 35 19 }

  condition:
    any of them
}