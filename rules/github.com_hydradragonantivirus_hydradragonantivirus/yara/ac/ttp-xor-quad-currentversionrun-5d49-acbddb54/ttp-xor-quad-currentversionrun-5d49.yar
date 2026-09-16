rule TTP_XOR_QUAD_CurrentVersionRun_5d49 {
  strings:
    $key_5d49 = { 0e 26 [2] 2a 28 [2] 01 04 [2] 2f 26 [2] 3b 3d [2] 34 27 [2] 2a 3a [2] 28 3b [2] 33 3d [2] 2f 3a [2] 33 15 }

  condition:
    any of them
}