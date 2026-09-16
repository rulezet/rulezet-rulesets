rule TTP_XOR_QUAD_CurrentVersionRun_5b48 {
  strings:
    $key_5b48 = { 08 27 [2] 2c 29 [2] 07 05 [2] 29 27 [2] 3d 3c [2] 32 26 [2] 2c 3b [2] 2e 3a [2] 35 3c [2] 29 3b [2] 35 14 }

  condition:
    any of them
}