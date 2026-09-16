rule TTP_XOR_QUAD_CurrentVersionRun_0b49 {
  strings:
    $key_0b49 = { 58 26 [2] 7c 28 [2] 57 04 [2] 79 26 [2] 6d 3d [2] 62 27 [2] 7c 3a [2] 7e 3b [2] 65 3d [2] 79 3a [2] 65 15 }

  condition:
    any of them
}