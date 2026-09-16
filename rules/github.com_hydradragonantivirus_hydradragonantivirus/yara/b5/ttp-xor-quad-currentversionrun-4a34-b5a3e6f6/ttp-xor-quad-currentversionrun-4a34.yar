rule TTP_XOR_QUAD_CurrentVersionRun_4a34 {
  strings:
    $key_4a34 = { 19 5b [2] 3d 55 [2] 16 79 [2] 38 5b [2] 2c 40 [2] 23 5a [2] 3d 47 [2] 3f 46 [2] 24 40 [2] 38 47 [2] 24 68 }

  condition:
    any of them
}