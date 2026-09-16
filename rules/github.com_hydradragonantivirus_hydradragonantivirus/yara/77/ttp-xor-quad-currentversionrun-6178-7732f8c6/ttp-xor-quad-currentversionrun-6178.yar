rule TTP_XOR_QUAD_CurrentVersionRun_6178 {
  strings:
    $key_6178 = { 32 17 [2] 16 19 [2] 3d 35 [2] 13 17 [2] 07 0c [2] 08 16 [2] 16 0b [2] 14 0a [2] 0f 0c [2] 13 0b [2] 0f 24 }

  condition:
    any of them
}