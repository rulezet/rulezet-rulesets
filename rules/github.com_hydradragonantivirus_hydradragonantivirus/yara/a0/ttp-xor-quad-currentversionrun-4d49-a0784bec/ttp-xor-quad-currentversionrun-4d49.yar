rule TTP_XOR_QUAD_CurrentVersionRun_4d49 {
  strings:
    $key_4d49 = { 1e 26 [2] 3a 28 [2] 11 04 [2] 3f 26 [2] 2b 3d [2] 24 27 [2] 3a 3a [2] 38 3b [2] 23 3d [2] 3f 3a [2] 23 15 }

  condition:
    any of them
}