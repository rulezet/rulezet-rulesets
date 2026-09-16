rule TTP_XOR_QUAD_CurrentVersionRun_7c49 {
  strings:
    $key_7c49 = { 2f 26 [2] 0b 28 [2] 20 04 [2] 0e 26 [2] 1a 3d [2] 15 27 [2] 0b 3a [2] 09 3b [2] 12 3d [2] 0e 3a [2] 12 15 }

  condition:
    any of them
}