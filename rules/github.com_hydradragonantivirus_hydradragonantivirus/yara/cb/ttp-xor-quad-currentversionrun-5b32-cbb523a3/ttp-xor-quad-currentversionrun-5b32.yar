rule TTP_XOR_QUAD_CurrentVersionRun_5b32 {
  strings:
    $key_5b32 = { 08 5d [2] 2c 53 [2] 07 7f [2] 29 5d [2] 3d 46 [2] 32 5c [2] 2c 41 [2] 2e 40 [2] 35 46 [2] 29 41 [2] 35 6e }

  condition:
    any of them
}