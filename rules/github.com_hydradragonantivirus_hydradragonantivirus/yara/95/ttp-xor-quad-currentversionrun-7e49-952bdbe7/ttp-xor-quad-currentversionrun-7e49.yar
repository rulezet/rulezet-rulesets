rule TTP_XOR_QUAD_CurrentVersionRun_7e49 {
  strings:
    $key_7e49 = { 2d 26 [2] 09 28 [2] 22 04 [2] 0c 26 [2] 18 3d [2] 17 27 [2] 09 3a [2] 0b 3b [2] 10 3d [2] 0c 3a [2] 10 15 }

  condition:
    any of them
}