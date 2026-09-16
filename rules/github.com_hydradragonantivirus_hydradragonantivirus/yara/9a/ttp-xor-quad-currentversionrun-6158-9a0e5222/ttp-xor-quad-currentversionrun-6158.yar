rule TTP_XOR_QUAD_CurrentVersionRun_6158 {
  strings:
    $key_6158 = { 32 37 [2] 16 39 [2] 3d 15 [2] 13 37 [2] 07 2c [2] 08 36 [2] 16 2b [2] 14 2a [2] 0f 2c [2] 13 2b [2] 0f 04 }

  condition:
    any of them
}