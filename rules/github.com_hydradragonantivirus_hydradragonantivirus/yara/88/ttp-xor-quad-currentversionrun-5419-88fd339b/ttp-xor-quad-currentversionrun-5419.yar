rule TTP_XOR_QUAD_CurrentVersionRun_5419 {
  strings:
    $key_5419 = { 07 76 [2] 23 78 [2] 08 54 [2] 26 76 [2] 32 6d [2] 3d 77 [2] 23 6a [2] 21 6b [2] 3a 6d [2] 26 6a [2] 3a 45 }

  condition:
    any of them
}