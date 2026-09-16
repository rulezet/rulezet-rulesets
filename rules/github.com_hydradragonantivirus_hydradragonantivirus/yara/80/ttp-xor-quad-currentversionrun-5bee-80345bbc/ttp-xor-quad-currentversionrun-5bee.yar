rule TTP_XOR_QUAD_CurrentVersionRun_5bee {
  strings:
    $key_5bee = { 08 81 [2] 2c 8f [2] 07 a3 [2] 29 81 [2] 3d 9a [2] 32 80 [2] 2c 9d [2] 2e 9c [2] 35 9a [2] 29 9d [2] 35 b2 }

  condition:
    any of them
}