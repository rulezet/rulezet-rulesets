rule TTP_XOR_QUAD_CurrentVersionRun_5249 {
  strings:
    $key_5249 = { 01 26 [2] 25 28 [2] 0e 04 [2] 20 26 [2] 34 3d [2] 3b 27 [2] 25 3a [2] 27 3b [2] 3c 3d [2] 20 3a [2] 3c 15 }

  condition:
    any of them
}