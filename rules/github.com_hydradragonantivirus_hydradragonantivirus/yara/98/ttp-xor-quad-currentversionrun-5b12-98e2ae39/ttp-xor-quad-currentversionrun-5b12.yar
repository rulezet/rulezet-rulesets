rule TTP_XOR_QUAD_CurrentVersionRun_5b12 {
  strings:
    $key_5b12 = { 08 7d [2] 2c 73 [2] 07 5f [2] 29 7d [2] 3d 66 [2] 32 7c [2] 2c 61 [2] 2e 60 [2] 35 66 [2] 29 61 [2] 35 4e }

  condition:
    any of them
}