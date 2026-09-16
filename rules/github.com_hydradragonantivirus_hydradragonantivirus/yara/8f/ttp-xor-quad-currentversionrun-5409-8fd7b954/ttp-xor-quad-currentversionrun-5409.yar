rule TTP_XOR_QUAD_CurrentVersionRun_5409 {
  strings:
    $key_5409 = { 07 66 [2] 23 68 [2] 08 44 [2] 26 66 [2] 32 7d [2] 3d 67 [2] 23 7a [2] 21 7b [2] 3a 7d [2] 26 7a [2] 3a 55 }

  condition:
    any of them
}