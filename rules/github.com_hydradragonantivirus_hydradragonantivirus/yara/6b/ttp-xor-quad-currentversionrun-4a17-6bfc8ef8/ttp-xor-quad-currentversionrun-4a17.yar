rule TTP_XOR_QUAD_CurrentVersionRun_4a17 {
  strings:
    $key_4a17 = { 19 78 [2] 3d 76 [2] 16 5a [2] 38 78 [2] 2c 63 [2] 23 79 [2] 3d 64 [2] 3f 65 [2] 24 63 [2] 38 64 [2] 24 4b }

  condition:
    any of them
}