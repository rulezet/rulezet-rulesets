rule TTP_XOR_QUAD_CurrentVersionRun_6145 {
  strings:
    $key_6145 = { 32 2a [2] 16 24 [2] 3d 08 [2] 13 2a [2] 07 31 [2] 08 2b [2] 16 36 [2] 14 37 [2] 0f 31 [2] 13 36 [2] 0f 19 }

  condition:
    any of them
}