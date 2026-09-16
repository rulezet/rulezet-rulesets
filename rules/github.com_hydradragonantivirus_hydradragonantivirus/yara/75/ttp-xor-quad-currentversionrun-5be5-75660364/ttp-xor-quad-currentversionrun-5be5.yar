rule TTP_XOR_QUAD_CurrentVersionRun_5be5 {
  strings:
    $key_5be5 = { 08 8a [2] 2c 84 [2] 07 a8 [2] 29 8a [2] 3d 91 [2] 32 8b [2] 2c 96 [2] 2e 97 [2] 35 91 [2] 29 96 [2] 35 b9 }

  condition:
    any of them
}