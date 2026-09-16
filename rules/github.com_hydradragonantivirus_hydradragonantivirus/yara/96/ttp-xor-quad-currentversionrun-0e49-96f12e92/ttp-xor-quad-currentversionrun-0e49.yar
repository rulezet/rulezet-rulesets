rule TTP_XOR_QUAD_CurrentVersionRun_0e49 {
  strings:
    $key_0e49 = { 5d 26 [2] 79 28 [2] 52 04 [2] 7c 26 [2] 68 3d [2] 67 27 [2] 79 3a [2] 7b 3b [2] 60 3d [2] 7c 3a [2] 60 15 }

  condition:
    any of them
}