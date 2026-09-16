rule TTP_XOR_QUAD_CurrentVersionRun_2049 {
  strings:
    $key_2049 = { 73 26 [2] 57 28 [2] 7c 04 [2] 52 26 [2] 46 3d [2] 49 27 [2] 57 3a [2] 55 3b [2] 4e 3d [2] 52 3a [2] 4e 15 }

  condition:
    any of them
}