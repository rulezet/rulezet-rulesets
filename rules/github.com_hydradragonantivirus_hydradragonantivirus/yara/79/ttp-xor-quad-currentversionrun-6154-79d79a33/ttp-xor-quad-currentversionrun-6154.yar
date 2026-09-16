rule TTP_XOR_QUAD_CurrentVersionRun_6154 {
  strings:
    $key_6154 = { 32 3b [2] 16 35 [2] 3d 19 [2] 13 3b [2] 07 20 [2] 08 3a [2] 16 27 [2] 14 26 [2] 0f 20 [2] 13 27 [2] 0f 08 }

  condition:
    any of them
}