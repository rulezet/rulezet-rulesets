rule TTP_XOR_QUAD_CurrentVersionRun_6c49 {
  strings:
    $key_6c49 = { 3f 26 [2] 1b 28 [2] 30 04 [2] 1e 26 [2] 0a 3d [2] 05 27 [2] 1b 3a [2] 19 3b [2] 02 3d [2] 1e 3a [2] 02 15 }

  condition:
    any of them
}