rule TTP_XOR_QUAD_CurrentVersionRun_5b34 {
  strings:
    $key_5b34 = { 08 5b [2] 2c 55 [2] 07 79 [2] 29 5b [2] 3d 40 [2] 32 5a [2] 2c 47 [2] 2e 46 [2] 35 40 [2] 29 47 [2] 35 68 }

  condition:
    any of them
}