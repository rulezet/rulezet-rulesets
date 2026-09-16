rule TTP_XOR_QUAD_CurrentVersionRun_5bf2 {
  strings:
    $key_5bf2 = { 08 9d [2] 2c 93 [2] 07 bf [2] 29 9d [2] 3d 86 [2] 32 9c [2] 2c 81 [2] 2e 80 [2] 35 86 [2] 29 81 [2] 35 ae }

  condition:
    any of them
}