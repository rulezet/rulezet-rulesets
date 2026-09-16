rule TTP_XOR_QUAD_CurrentVersionRun_6a49 {
  strings:
    $key_6a49 = { 39 26 [2] 1d 28 [2] 36 04 [2] 18 26 [2] 0c 3d [2] 03 27 [2] 1d 3a [2] 1f 3b [2] 04 3d [2] 18 3a [2] 04 15 }

  condition:
    any of them
}