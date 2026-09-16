rule TTP_XOR_QUAD_CurrentVersionRun_5b28 {
  strings:
    $key_5b28 = { 08 47 [2] 2c 49 [2] 07 65 [2] 29 47 [2] 3d 5c [2] 32 46 [2] 2c 5b [2] 2e 5a [2] 35 5c [2] 29 5b [2] 35 74 }

  condition:
    any of them
}