rule TTP_XOR_QUAD_CurrentVersionRun_5b68 {
  strings:
    $key_5b68 = { 08 07 [2] 2c 09 [2] 07 25 [2] 29 07 [2] 3d 1c [2] 32 06 [2] 2c 1b [2] 2e 1a [2] 35 1c [2] 29 1b [2] 35 34 }

  condition:
    any of them
}