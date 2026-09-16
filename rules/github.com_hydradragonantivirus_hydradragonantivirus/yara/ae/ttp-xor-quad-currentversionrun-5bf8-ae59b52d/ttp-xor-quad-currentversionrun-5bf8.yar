rule TTP_XOR_QUAD_CurrentVersionRun_5bf8 {
  strings:
    $key_5bf8 = { 08 97 [2] 2c 99 [2] 07 b5 [2] 29 97 [2] 3d 8c [2] 32 96 [2] 2c 8b [2] 2e 8a [2] 35 8c [2] 29 8b [2] 35 a4 }

  condition:
    any of them
}