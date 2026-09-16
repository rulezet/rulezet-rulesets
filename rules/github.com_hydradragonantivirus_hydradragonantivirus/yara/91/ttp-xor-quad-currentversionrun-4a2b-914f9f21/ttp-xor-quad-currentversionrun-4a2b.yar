rule TTP_XOR_QUAD_CurrentVersionRun_4a2b {
  strings:
    $key_4a2b = { 19 44 [2] 3d 4a [2] 16 66 [2] 38 44 [2] 2c 5f [2] 23 45 [2] 3d 58 [2] 3f 59 [2] 24 5f [2] 38 58 [2] 24 77 }

  condition:
    any of them
}