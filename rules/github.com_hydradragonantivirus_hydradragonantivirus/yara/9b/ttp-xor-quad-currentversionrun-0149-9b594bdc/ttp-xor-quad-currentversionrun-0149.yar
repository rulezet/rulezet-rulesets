rule TTP_XOR_QUAD_CurrentVersionRun_0149 {
  strings:
    $key_0149 = { 52 26 [2] 76 28 [2] 5d 04 [2] 73 26 [2] 67 3d [2] 68 27 [2] 76 3a [2] 74 3b [2] 6f 3d [2] 73 3a [2] 6f 15 }

  condition:
    any of them
}