rule TTP_XOR_QUAD_CurrentVersionRun_6135 {
  strings:
    $key_6135 = { 32 5a [2] 16 54 [2] 3d 78 [2] 13 5a [2] 07 41 [2] 08 5b [2] 16 46 [2] 14 47 [2] 0f 41 [2] 13 46 [2] 0f 69 }

  condition:
    any of them
}