rule TTP_XOR_QUAD_CurrentVersionRun_6105 {
  strings:
    $key_6105 = { 32 6a [2] 16 64 [2] 3d 48 [2] 13 6a [2] 07 71 [2] 08 6b [2] 16 76 [2] 14 77 [2] 0f 71 [2] 13 76 [2] 0f 59 }

  condition:
    any of them
}