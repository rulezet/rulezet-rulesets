rule TTP_XOR_QUAD_CurrentVersionRun_4f24 {
  strings:
    $key_4f24 = { 1c 4b [2] 38 45 [2] 13 69 [2] 3d 4b [2] 29 50 [2] 26 4a [2] 38 57 [2] 3a 56 [2] 21 50 [2] 3d 57 [2] 21 78 }

  condition:
    any of them
}