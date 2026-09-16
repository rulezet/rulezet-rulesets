rule TTP_XOR_QUAD_CurrentVersionRun_1e49 {
  strings:
    $key_1e49 = { 4d 26 [2] 69 28 [2] 42 04 [2] 6c 26 [2] 78 3d [2] 77 27 [2] 69 3a [2] 6b 3b [2] 70 3d [2] 6c 3a [2] 70 15 }

  condition:
    any of them
}