rule TTP_XOR_QUAD_CurrentVersionRun_4c49 {
  strings:
    $key_4c49 = { 1f 26 [2] 3b 28 [2] 10 04 [2] 3e 26 [2] 2a 3d [2] 25 27 [2] 3b 3a [2] 39 3b [2] 22 3d [2] 3e 3a [2] 22 15 }

  condition:
    any of them
}