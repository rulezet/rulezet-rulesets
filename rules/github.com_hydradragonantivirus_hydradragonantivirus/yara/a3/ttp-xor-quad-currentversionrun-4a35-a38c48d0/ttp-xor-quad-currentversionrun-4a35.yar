rule TTP_XOR_QUAD_CurrentVersionRun_4a35 {
  strings:
    $key_4a35 = { 19 5a [2] 3d 54 [2] 16 78 [2] 38 5a [2] 2c 41 [2] 23 5b [2] 3d 46 [2] 3f 47 [2] 24 41 [2] 38 46 [2] 24 69 }

  condition:
    any of them
}