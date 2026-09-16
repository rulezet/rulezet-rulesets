rule TTP_XOR_QUAD_CurrentVersionRun_4af7 {
  strings:
    $key_4af7 = { 19 98 [2] 3d 96 [2] 16 ba [2] 38 98 [2] 2c 83 [2] 23 99 [2] 3d 84 [2] 3f 85 [2] 24 83 [2] 38 84 [2] 24 ab }

  condition:
    any of them
}