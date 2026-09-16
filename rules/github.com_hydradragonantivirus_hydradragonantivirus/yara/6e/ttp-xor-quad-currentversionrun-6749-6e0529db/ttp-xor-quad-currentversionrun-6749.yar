rule TTP_XOR_QUAD_CurrentVersionRun_6749 {
  strings:
    $key_6749 = { 34 26 [2] 10 28 [2] 3b 04 [2] 15 26 [2] 01 3d [2] 0e 27 [2] 10 3a [2] 12 3b [2] 09 3d [2] 15 3a [2] 09 15 }

  condition:
    any of them
}