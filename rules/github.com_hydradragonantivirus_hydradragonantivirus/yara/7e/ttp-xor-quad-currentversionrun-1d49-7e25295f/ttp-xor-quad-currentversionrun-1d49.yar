rule TTP_XOR_QUAD_CurrentVersionRun_1d49 {
  strings:
    $key_1d49 = { 4e 26 [2] 6a 28 [2] 41 04 [2] 6f 26 [2] 7b 3d [2] 74 27 [2] 6a 3a [2] 68 3b [2] 73 3d [2] 6f 3a [2] 73 15 }

  condition:
    any of them
}