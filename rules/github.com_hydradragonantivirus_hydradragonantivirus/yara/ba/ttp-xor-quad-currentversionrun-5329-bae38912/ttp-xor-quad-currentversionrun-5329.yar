rule TTP_XOR_QUAD_CurrentVersionRun_5329 {
  strings:
    $key_5329 = { 00 46 [2] 24 48 [2] 0f 64 [2] 21 46 [2] 35 5d [2] 3a 47 [2] 24 5a [2] 26 5b [2] 3d 5d [2] 21 5a [2] 3d 75 }

  condition:
    any of them
}