rule TTP_XOR_QUAD_CurrentVersionRun_5be0 {
  strings:
    $key_5be0 = { 08 8f [2] 2c 81 [2] 07 ad [2] 29 8f [2] 3d 94 [2] 32 8e [2] 2c 93 [2] 2e 92 [2] 35 94 [2] 29 93 [2] 35 bc }

  condition:
    any of them
}