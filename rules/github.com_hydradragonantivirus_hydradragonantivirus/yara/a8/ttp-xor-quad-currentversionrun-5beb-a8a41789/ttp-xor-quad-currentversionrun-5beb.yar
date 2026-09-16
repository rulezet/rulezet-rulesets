rule TTP_XOR_QUAD_CurrentVersionRun_5beb {
  strings:
    $key_5beb = { 08 84 [2] 2c 8a [2] 07 a6 [2] 29 84 [2] 3d 9f [2] 32 85 [2] 2c 98 [2] 2e 99 [2] 35 9f [2] 29 98 [2] 35 b7 }

  condition:
    any of them
}