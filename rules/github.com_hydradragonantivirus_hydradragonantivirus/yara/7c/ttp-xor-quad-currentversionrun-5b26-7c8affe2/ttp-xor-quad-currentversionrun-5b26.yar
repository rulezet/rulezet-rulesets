rule TTP_XOR_QUAD_CurrentVersionRun_5b26 {
  strings:
    $key_5b26 = { 08 49 [2] 2c 47 [2] 07 6b [2] 29 49 [2] 3d 52 [2] 32 48 [2] 2c 55 [2] 2e 54 [2] 35 52 [2] 29 55 [2] 35 7a }

  condition:
    any of them
}