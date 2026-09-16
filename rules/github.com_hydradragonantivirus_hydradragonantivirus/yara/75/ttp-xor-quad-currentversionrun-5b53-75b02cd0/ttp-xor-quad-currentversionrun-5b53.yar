rule TTP_XOR_QUAD_CurrentVersionRun_5b53 {
  strings:
    $key_5b53 = { 08 3c [2] 2c 32 [2] 07 1e [2] 29 3c [2] 3d 27 [2] 32 3d [2] 2c 20 [2] 2e 21 [2] 35 27 [2] 29 20 [2] 35 0f }

  condition:
    any of them
}