rule TTP_XOR_QUAD_CurrentVersionRun_5bf6 {
  strings:
    $key_5bf6 = { 08 99 [2] 2c 97 [2] 07 bb [2] 29 99 [2] 3d 82 [2] 32 98 [2] 2c 85 [2] 2e 84 [2] 35 82 [2] 29 85 [2] 35 aa }

  condition:
    any of them
}