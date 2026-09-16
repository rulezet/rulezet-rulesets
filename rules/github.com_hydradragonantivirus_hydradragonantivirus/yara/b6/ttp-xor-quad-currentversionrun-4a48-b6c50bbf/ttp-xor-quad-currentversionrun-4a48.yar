rule TTP_XOR_QUAD_CurrentVersionRun_4a48 {
  strings:
    $key_4a48 = { 19 27 [2] 3d 29 [2] 16 05 [2] 38 27 [2] 2c 3c [2] 23 26 [2] 3d 3b [2] 3f 3a [2] 24 3c [2] 38 3b [2] 24 14 }

  condition:
    any of them
}