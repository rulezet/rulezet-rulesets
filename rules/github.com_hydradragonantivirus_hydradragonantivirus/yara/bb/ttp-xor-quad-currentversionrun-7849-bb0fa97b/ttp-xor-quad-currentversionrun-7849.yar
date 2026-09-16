rule TTP_XOR_QUAD_CurrentVersionRun_7849 {
  strings:
    $key_7849 = { 2b 26 [2] 0f 28 [2] 24 04 [2] 0a 26 [2] 1e 3d [2] 11 27 [2] 0f 3a [2] 0d 3b [2] 16 3d [2] 0a 3a [2] 16 15 }

  condition:
    any of them
}