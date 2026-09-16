rule TTP_XOR_QUAD_CurrentVersionRun_6d49 {
  strings:
    $key_6d49 = { 3e 26 [2] 1a 28 [2] 31 04 [2] 1f 26 [2] 0b 3d [2] 04 27 [2] 1a 3a [2] 18 3b [2] 03 3d [2] 1f 3a [2] 03 15 }

  condition:
    any of them
}