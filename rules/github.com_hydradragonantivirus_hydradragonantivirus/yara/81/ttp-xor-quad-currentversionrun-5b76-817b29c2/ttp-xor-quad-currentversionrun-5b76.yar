rule TTP_XOR_QUAD_CurrentVersionRun_5b76 {
  strings:
    $key_5b76 = { 08 19 [2] 2c 17 [2] 07 3b [2] 29 19 [2] 3d 02 [2] 32 18 [2] 2c 05 [2] 2e 04 [2] 35 02 [2] 29 05 [2] 35 2a }

  condition:
    any of them
}