rule TTP_XOR_QUAD_CurrentVersionRun_1b49 {
  strings:
    $key_1b49 = { 48 26 [2] 6c 28 [2] 47 04 [2] 69 26 [2] 7d 3d [2] 72 27 [2] 6c 3a [2] 6e 3b [2] 75 3d [2] 69 3a [2] 75 15 }

  condition:
    any of them
}