rule TTP_XOR_QUAD_CurrentVersionRun_6147 {
  strings:
    $key_6147 = { 32 28 [2] 16 26 [2] 3d 0a [2] 13 28 [2] 07 33 [2] 08 29 [2] 16 34 [2] 14 35 [2] 0f 33 [2] 13 34 [2] 0f 1b }

  condition:
    any of them
}